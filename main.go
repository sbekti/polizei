package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	ciliumClientSet "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	bindAddr   string
	bindPort   int
	redisAddr  string
	redisPwd   string
	kubeconfig string
	netpolNs   string
	netpolName string
	logLevel   string

	ctx = context.Background()

	config *rest.Config
)

type modifyBlocklistReq struct {
	CIDR string `json:"cidr"`
}

type modifyBlocklistResp struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type getBlocklistResp struct {
	Success bool     `json:"success"`
	Message string   `json:"message"`
	CIDRs   []string `json:"cidrs"`
}

func redisHandler(c *redis.Client,
	f func(c *redis.Client, w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f(c, w, r) })
}

func sendModifyBlocklistResponse(w http.ResponseWriter, statusCode int, success bool,
	message string) {
	resp := modifyBlocklistResp{
		Success: success,
		Message: message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

func validateCIDR(cidr string) error {
	if cidr == "" {
		return errors.New("bad request: an empty CIDR was given")
	}

	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("bad request: invalid CIDR was given: %s", cidr)
	}

	return nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "hello from polizei!")
}

func handleGetBlocklist(c *redis.Client, w http.ResponseWriter, r *http.Request) {
	key := "polizei:" + netpolNs
	members := c.SMembers(ctx, key)
	if members.Err() != nil {
		log.Errorf("handleGetBlocklist: failed to get members of set %s in redis: %s\n", key, members.Err())
		resp := getBlocklistResp{
			Success: false,
			Message: "Internal server error, please try again.",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := getBlocklistResp{
		Success: true,
		CIDRs:   members.Val(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func handleBlock(c *redis.Client, w http.ResponseWriter, r *http.Request) {
	var mbr modifyBlocklistReq

	err := json.NewDecoder(r.Body).Decode(&mbr)
	if err != nil {
		sendModifyBlocklistResponse(w, http.StatusInternalServerError, false,
			fmt.Sprintf("Unable to decode JSON request: %s", err))
		return
	}

	err = validateCIDR(mbr.CIDR)
	if err != nil {
		sendModifyBlocklistResponse(w, http.StatusBadRequest, false,
			err.Error())
		return
	}

	key := "polizei:" + netpolNs
	err = c.SAdd(ctx, key, mbr.CIDR).Err()
	if err != nil {
		log.Errorf("handleBlock: Failed to add CIDR %s to set %s in redis: %s\n", mbr.CIDR, key, err)
		sendModifyBlocklistResponse(w, http.StatusInternalServerError, false,
			"Internal server error, please try again.")
		return
	}

	updateNetpol(c)

	log.Infof("handleBlock: Added CIDR to blocklist: %s\n", mbr.CIDR)

	resp := modifyBlocklistResp{
		Success: true,
		Message: fmt.Sprintf("Successfully added %s to blocklist", mbr.CIDR),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func handleUnblock(c *redis.Client, w http.ResponseWriter, r *http.Request) {
	var mbr modifyBlocklistReq

	err := json.NewDecoder(r.Body).Decode(&mbr)
	if err != nil {
		sendModifyBlocklistResponse(w, http.StatusInternalServerError, false,
			fmt.Sprintf("Unable to decode JSON request: %s", err))
		return
	}

	err = validateCIDR(mbr.CIDR)
	if err != nil {
		sendModifyBlocklistResponse(w, http.StatusBadRequest, false,
			err.Error())
		return
	}

	key := "polizei:" + netpolNs
	err = c.SRem(ctx, key, mbr.CIDR).Err()
	if err != nil {
		log.Errorf("handleUnblock: Failed to remove CIDR %s from set %s in redis: %s\n", mbr.CIDR, key, err)
		sendModifyBlocklistResponse(w, http.StatusInternalServerError, false,
			"Internal server error, please try again.")
		return
	}

	updateNetpol(c)

	log.Infof("handleUnblock: Removed CIDR from blocklist: %s\n", mbr.CIDR)

	resp := modifyBlocklistResp{
		Success: true,
		Message: fmt.Sprintf("Successfully removed %s from blocklist", mbr.CIDR),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func updateNetpol(c *redis.Client) {
	key := "polizei:" + netpolNs
	members := c.SMembers(ctx, key)
	if members.Err() != nil {
		log.Errorf("updateNetpol: failed to get members of set %s in redis: %s\n", key, members.Err())
		return
	}

	ciliumClient, err := ciliumClientSet.NewForConfig(config)
	if err != nil {
		log.Errorf("updateNetpol: failed to create cilium client: %s\n", err)
		return
	}

	cnp, err := ciliumClient.CiliumV2().CiliumNetworkPolicies(netpolNs).Get(context.TODO(), netpolName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("updateNetpol: failed to get cilium netpol %s in namespace %s: %s\n", netpolName, netpolNs, err)
		return
	}

	var cidrs = []api.CIDR{}
	for _, member := range members.Val() {
		cidrs = append(cidrs, api.CIDR(member))
	}

	ingDenyRule := api.IngressDenyRule{
		IngressCommonRule: api.IngressCommonRule{
			FromCIDR: cidrs,
		},
	}

	cnp.Spec.IngressDeny = []api.IngressDenyRule{ingDenyRule}

	_, err = ciliumClient.CiliumV2().CiliumNetworkPolicies(netpolNs).Update(context.TODO(), cnp, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("updateNetpol: failed to update cilium netpol %s in namespace %s: %s\n", netpolName, netpolNs, err)
		return
	}

	log.Infof("updateNetpol: successfully wrote %d entries to cilium netpol %s\n", len(cidrs), netpolName)
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "bind-addr",
			Value:       "0.0.0.0",
			Usage:       "address to bind to",
			EnvVar:      "BIND_ADDR",
			Destination: &bindAddr,
		},
		&cli.IntFlag{
			Name:        "bind-port",
			Value:       8080,
			Usage:       "port number to bind to",
			EnvVar:      "BIND_PORT",
			Destination: &bindPort,
		},
		cli.StringFlag{
			Name:        "log-level",
			Value:       "info",
			Usage:       "log level",
			EnvVar:      "LOG_LEVEL",
			Destination: &logLevel,
		},
		cli.StringFlag{
			Name:        "redis-addr",
			Value:       "localhost:6379",
			Usage:       "redis address",
			EnvVar:      "REDIS_ADDR",
			Destination: &redisAddr,
		},
		cli.StringFlag{
			Name:        "redis-pwd",
			Value:       "",
			Usage:       "redis password",
			EnvVar:      "REDIS_PWD",
			Destination: &redisPwd,
		},
		cli.StringFlag{
			Name:        "kubeconfig",
			Value:       "",
			Usage:       "kubeconfig",
			EnvVar:      "KUBECONFIG",
			Destination: &kubeconfig,
		},
		cli.StringFlag{
			Name:        "netpol-ns",
			Value:       "default",
			Usage:       "netpol namespace",
			EnvVar:      "NETPOL_NS",
			Destination: &netpolNs,
		},
		cli.StringFlag{
			Name:        "netpol-name",
			Value:       "",
			Usage:       "cilium network policy name",
			EnvVar:      "NETPOL_NAME",
			Destination: &netpolName,
		},
	}

	app.Action = func(c *cli.Context) error {
		if kubeconfig == "" {
			c, err := rest.InClusterConfig()
			if err != nil {
				log.Fatal(err.Error())
			}
			config = c
		} else {
			c, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				log.Fatal(err.Error())
			}
			config = c
		}

		level, err := log.ParseLevel(logLevel)
		if err != nil {
			log.Fatal(err)
		}
		log.SetLevel(level)

		rdb := redis.NewClient(&redis.Options{
			Addr:     redisAddr,
			Password: redisPwd,
			DB:       0, // use default DB
		})

		log.Infof("server listening on port %d\n", bindPort)
		router := mux.NewRouter()
		router.HandleFunc("/", handleIndex).Methods("GET")
		router.Handle("/block", redisHandler(rdb, handleGetBlocklist)).Methods("GET")
		router.Handle("/block", redisHandler(rdb, handleBlock)).Methods("POST")
		router.Handle("/block", redisHandler(rdb, handleUnblock)).Methods("DELETE")

		srv := &http.Server{
			Handler:      router,
			Addr:         bindAddr + ":" + strconv.Itoa(bindPort),
			WriteTimeout: 30 * time.Second,
			ReadTimeout:  30 * time.Second,
		}
		log.Fatal(srv.ListenAndServe())
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
