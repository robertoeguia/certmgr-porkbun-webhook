package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	k8sv1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-resty/resty/v2"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

const (
	providerName       = "porkbun"
	porkbunURIEndpoint = "https://api.porkbun.com/api/json/v3"
)

func main() {
	log.Printf("GROUP_NAME: %v", GroupName)
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&porkbunDNSSolver{},
	)
}

type porkbunRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
	Prio    string `json:"prio"`
	Notes   string `json:"notes"`
}

type porkbunCreateUpdateRecord struct {
	SecretAPIKey string `json:"secretapikey"`
	APIKey       string `json:"apikey"`
	Name         string `json:"name"`
	TTL          string `json:"ttl"`
	Type         string `json:"type"`
	Content      string `json:"content"`
}

// porkbunDNSSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type porkbunDNSSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	k8sClient *kubernetes.Clientset

	restClient *resty.Client
}

// porkbunDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type porkbunDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	APIKeysSecretRef k8sv1.SecretReference `json:"apiKeysSecretRef"`

	APIkey       string `json:"apiKey"`
	APISecretKey string `json:"apiSecretKey"`
}

// #region private

// Validate necessary configurations are present before attempting to
// create DNS record
func (c *porkbunDNSSolver) validate(cfg *porkbunDNSProviderConfig) error {
	if cfg.APIKeysSecretRef.Name != "" || (cfg.APIkey != "" && cfg.APISecretKey != "") {
		return nil
	}

	return errors.New("API keys or secret not provided")
}

// If validation succeeds, load API keys from json configuration or from K8s Secret Reference
func (c *porkbunDNSSolver) loadApiKeys(cfg *porkbunDNSProviderConfig, ch *v1alpha1.ChallengeRequest) error {

	// If both keys are passed via issuer configuration
	// skip loading from secret
	if cfg.APIkey != "" && cfg.APISecretKey != "" {
		return nil
	}

	var ns string
	if cfg.APIKeysSecretRef.Namespace != "" {
		ns = cfg.APIKeysSecretRef.Namespace
	} else {
		ns = ch.ResourceNamespace
	}

	sec, err := c.k8sClient.CoreV1().Secrets(ns).
		Get(context.TODO(), cfg.APIKeysSecretRef.Name, metaV1.GetOptions{})
	if err != nil {
		return err
	}

	// Only check secret for API key if it was not provided
	// in the issuer configuration
	apiKeyBytes, ok := sec.Data["apiKey"]
	if cfg.APIkey == "" && !ok {
		return fmt.Errorf("key %v not found in secret \"%s/%s\"", "apiKey", cfg.APIKeysSecretRef.Name, ns)
	}

	// Only check secret for API secret key if it was not provided
	// in the issuer configuration
	apiSecretKeyBytes, ok := sec.Data["apiSecretKey"]
	if cfg.APISecretKey == "" && !ok {
		return fmt.Errorf("key %v not found in secret \"%s/%s\"", "apiSecretKey", cfg.APIKeysSecretRef.Name, ns)
	}

	cfg.APIkey = string(apiKeyBytes)
	cfg.APISecretKey = string(apiSecretKeyBytes)

	return nil
}

// Check if record exists
func (c *porkbunDNSSolver) searchRecords(cfg *porkbunDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (*porkbunRecord, error) {
	request := c.restClient.NewRequest().EnableTrace()
	fqdn := strings.TrimRight(ch.ResolvedFQDN, ".")
	apiEndpoint := fmt.Sprintf("%v/dns/retrieve/%v", porkbunURIEndpoint, strings.TrimRight(ch.ResolvedZone, "."))

	body := map[string]string{
		"secretapikey": cfg.APISecretKey,
		"apikey":       cfg.APIkey,
	}

	log.Printf("Searching porkbun for existing record: %v", fqdn)

	request.SetBody(body)
	response, err := request.Post(apiEndpoint)

	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	if response.StatusCode() != 200 {
		output := fmt.Sprintf("{ requested_record: '%v', ", strings.TrimRight(ch.ResolvedFQDN, "."))
		output += fmt.Sprintf("status_code: '%v', status: '%v', ", response.StatusCode(), response.Status())
		output += fmt.Sprintf("response: '%v' }", response.String())
		err := errors.New(output)
		log.Println(err.Error())
		return nil, err
	}

	var result map[string]any

	json.Unmarshal(response.Body(), &result)

	for _, item := range result["records"].([]interface{}) {
		if record, ok := item.(map[string]any); ok {
			if record["name"] == fqdn && record["content"] == ch.Key {
				log.Printf("Existing record found: %v", record)
				return &porkbunRecord{
					ID:      record["id"].(string),
					Name:    record["name"].(string),
					Type:    record["type"].(string),
					Content: record["content"].(string),
					TTL:     record["ttl"].(string),
				}, nil
			}
		}
	}

	log.Printf("Record: %v does not exist", fqdn)
	return nil, nil
}

func (c *porkbunDNSSolver) addTxtRecord(cfg *porkbunDNSProviderConfig, ch *v1alpha1.ChallengeRequest) (*porkbunRecord, error) {
	zone := strings.TrimRight(ch.ResolvedZone, ".")
	fqdn := strings.TrimRight(ch.ResolvedFQDN, ".")
	name := strings.TrimRight(strings.TrimSuffix(fqdn, zone), ".")

	log.Printf("Adding TXT record: %v", fqdn)
	apiEndpoint := fmt.Sprintf("%v/dns/create/%v", porkbunURIEndpoint, zone)
	log.Println(apiEndpoint)

	body := &porkbunCreateUpdateRecord{
		SecretAPIKey: cfg.APISecretKey,
		APIKey:       cfg.APIkey,
		Name:         name,
		TTL:          "600",
		Type:         "TXT",
		Content:      ch.Key,
	}

	jsonString, _ := json.Marshal(body)
	response, err := c.restClient.NewRequest().SetBody(jsonString).Post(apiEndpoint)
	if err != nil {
		return nil, err
	}

	log.Println(response)

	if response.StatusCode() == 400 {
		return nil, fmt.Errorf("error updating TXT record: %v", response)
	} else {
		log.Println("TXT record updated successfully")
	}

	return nil, nil
}

func (c *porkbunDNSSolver) updateTxtRecord(cfg *porkbunDNSProviderConfig, ch *v1alpha1.ChallengeRequest, r *porkbunRecord) error {
	zone := strings.TrimRight(ch.ResolvedZone, ".")
	fqdn := strings.TrimRight(ch.ResolvedFQDN, ".")
	name := strings.TrimRight(strings.TrimSuffix(fqdn, zone), ".")

	log.Printf("Updating TXT record: %v", fqdn)
	apiEndpoint := fmt.Sprintf("%v/dns/edit/%v/%v", porkbunURIEndpoint, zone, r.ID)
	log.Println(apiEndpoint)

	body := &porkbunCreateUpdateRecord{
		SecretAPIKey: cfg.APISecretKey,
		APIKey:       cfg.APIkey,
		Name:         name,
		TTL:          "600",
		Type:         "TXT",
		Content:      ch.Key,
	}

	jsonString, _ := json.Marshal(body)
	response, err := c.restClient.NewRequest().SetBody(jsonString).Post(apiEndpoint)
	if err != nil {
		return err
	}

	if response.StatusCode() == 400 {
		return fmt.Errorf("error updating TXT record: %v", response)
	} else {
		log.Println("TXT record updated successfully")
	}

	return nil
}

func (c *porkbunDNSSolver) deleteTXTRecord(cfg *porkbunDNSProviderConfig, ch *v1alpha1.ChallengeRequest, r *porkbunRecord) error {
	zone := strings.TrimRight(ch.ResolvedZone, ".")
	fqdn := strings.TrimRight(ch.ResolvedFQDN, ".")

	log.Printf("Deleting TXT record: %v", fqdn)
	apiEndpoint := fmt.Sprintf("%v/dns/delete/%v/%v", porkbunURIEndpoint, zone, r.ID)
	log.Println(apiEndpoint)

	body := map[string]string{
		"secretapikey": cfg.APISecretKey,
		"apikey":       cfg.APIkey,
	}

	jsonString, _ := json.Marshal(body)
	response, err := c.restClient.NewRequest().SetBody(jsonString).Post(apiEndpoint)
	if err != nil {
		return err
	}

	if response.StatusCode() == 400 {
		return fmt.Errorf("error deleting TXT record: %v", response)
	} else {
		log.Println("TXT record deleted successfully")
	}

	return nil
}

// #endregion

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *porkbunDNSSolver) Name() string {
	return providerName
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *porkbunDNSSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	if err = c.validate(&cfg); err != nil {
		return err
	}

	if err := c.loadApiKeys(&cfg, ch); err != nil {
		return err
	}

	// TODO: add code that sets a record in the DNS provider's console
	var result *porkbunRecord
	if result, err = c.searchRecords(&cfg, ch); err != nil {
		return err
	}

	if result != nil {
		if result.Content != ch.Key {
			err = c.updateTxtRecord(&cfg, ch, result)
			if err != nil {
				return err
			}
		}
	} else {
		_, err = c.addTxtRecord(&cfg, ch)
		if err != nil {
			return err
		}
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *porkbunDNSSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	if err = c.validate(&cfg); err != nil {
		return err
	}

	if err := c.loadApiKeys(&cfg, ch); err != nil {
		return err
	}

	var result *porkbunRecord
	if result, err = c.searchRecords(&cfg, ch); err != nil {
		return err
	}

	if result != nil {
		err = c.deleteTXTRecord(&cfg, ch, result)
		if err != nil {
			return err
		}
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *porkbunDNSSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.k8sClient = cl
	c.restClient = resty.New()

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (porkbunDNSProviderConfig, error) {
	cfg := porkbunDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
