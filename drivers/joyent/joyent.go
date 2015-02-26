package joyent

import (
	"fmt"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/codegangsta/cli"
	"github.com/docker/machine/drivers"
	"github.com/docker/machine/state"
	"github.com/docker/machine/utils"
	"os/exec"
	"path"

	"crypto/tls"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	JoyentDockerPort   string = "2376"
	JoyentDockerDomain string = "api.joyentcloud.com"
)

type Driver struct {
	Region      string
	Account     string
	PrivateKey  string
	MachineName string
	storePath   string
}

type CreateFlags struct {
	Region     *string
	Account    *string
	PrivateKey *string
}

func init() {
	drivers.Register("joyent", &drivers.RegisteredDriver{
		New:            NewDriver,
		GetCreateFlags: GetCreateFlags,
	})
}

func GetCreateFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   "joyent-region",
			Usage:  "Joyent Datacenter",
			Value:  "us-west-2",
			EnvVar: "SDC_REGION",
		},
		cli.StringFlag{
			Name:   "joyent-account",
			Usage:  "Joyent Account",
			Value:  "",
			EnvVar: "SDC_ACCOUNT",
		},
		cli.StringFlag{
			Name:   "joyent-key",
			Usage:  "Private Ssh Key",
			Value:  "~/.ssh/id_rsa",
			EnvVar: "SDC_KEY",
		},
	}
}
func NewDriver(machineName string, storePath string, caCert string, privateKey string) (drivers.Driver, error) {
	return &Driver{
		MachineName: machineName,
		storePath:   storePath,
	}, nil
}

func (d *Driver) DriverName() string {
	return "joyent"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.Region = flags.String("joyent-region")
	d.Account = flags.String("joyent-account")
	d.PrivateKey = flags.String("joyent-key")

	if d.Account == "" {
		return fmt.Errorf("Please specify account")
	}

	if strings.HasPrefix(d.PrivateKey, "~") {
		d.PrivateKey = strings.Replace(d.PrivateKey, "~", utils.GetHomeDir(), 1)
	}
	return nil
}

func GenerateCertificate(key *rsa.PrivateKey, commonName string) error {
	var certFile = path.Join(utils.GetMachineCertDir(), "cert.pem")
	var keyFile = path.Join(utils.GetMachineCertDir(), "key.pem")

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		SignatureAlgorithm:    x509.SHA512WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certOut, _ := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	keyOut, _ := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certOut.Close()
	keyOut.Close()

	return nil
}

func (d *Driver) GetURL() (string, error) {
	return fmt.Sprintf("tcp://%s.%s:%s", d.Region, JoyentDockerDomain, JoyentDockerPort), nil
}

func (d *Driver) GetIP() (string, error) {
	return fmt.Sprintf("%s.%s", d.Region, JoyentDockerDomain), nil
}

func (d *Driver) GetState() (state.State, error) {
	cert, err := tls.LoadX509KeyPair(path.Join(d.storePath, "cert.pem"), path.Join(d.storePath, "key.pem"))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			},
		},
	}
	ip, _ := d.GetIP()

	resp, err := client.Get(fmt.Sprintf("https://%s:%s/_ping", ip, JoyentDockerPort))
	if err != nil {
		return state.Error, nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if string(body[:]) == "OK" {
		return state.Running, nil
	}
	return state.None, nil
}

func (d *Driver) PreCreateCheck() error {
	return nil
}

func (d *Driver) Create() error {
	pemBytes, _ := ioutil.ReadFile(d.PrivateKey)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("SSH Key not found")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	return GenerateCertificate(privateKey, d.Account)
}

func (d *Driver) Start() error {
	return nil
}

func (d *Driver) Stop() error {
	return nil
}

func (d *Driver) Remove() error {
	return nil
}

func (d *Driver) Restart() error {
	return nil
}

func (d *Driver) Kill() error {
	return nil
}

func (d *Driver) StartDocker() error {
	return nil
}

func (d *Driver) StopDocker() error {
	return nil
}

func (d *Driver) GetDockerConfigDir() string {
	return d.storePath
}

func (d *Driver) Upgrade() error {
	return nil
}

func (d *Driver) GetSSHCommand(args ...string) (*exec.Cmd, error) {
	return exec.Command("true"), nil
}
