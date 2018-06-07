package main

import (
	"math"
	"fmt"
	"os"
	"time"
	"net"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	api "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"golang.org/x/net/context"
	"istio.io/istio/pkg/log"
)

type (
	cliOptions struct {
		UdsPath              string
	}

	Secret struct {
		certificateChain 		string
		privateKey 					string
	}

	// SecretServerInfo contains identity and grpc.Server instances for the UDS socket
	SecretServerInfo struct {
		// identity attached to the server
		identity string
		// grpc server instance
		server *grpc.Server
	}

	// SDSServer implements api.SecretDiscoveryServiceServer that listens on a
	// list of Unix Domain Sockets.
	SDSServer struct {
		// Specifies a map of Unix Domain Socket paths and the SecretServerInfo.
		// Each UDS path identifies the identity for which the workload will
		// request X.509 key/cert from this server. This path should only be
		// accessible by such workload.
		udsServerMap map[string]*SecretServerInfo

		// current certificate chain and private key version number
		version string

		previousRequestTime time.Time;
	}

)

const (
	// key for UDS path in gRPC context metadata map.
	udsPathKey = ":authority"

	// SecretTypeURL defines the type URL for Envoy secret proto.
	SecretTypeURL = "type.googleapis.com/envoy.api.v2.auth.Secret"

	// SecretName defines the type of the secrets to fetch from the SDS server.
	SecretName = "SPKI"
)

var (
	opts = cliOptions{}

	rootCmd = &cobra.Command{
		Use:   "istio_ca",
		Short: "Istio Certificate Authority (CA)",
		Run: func(cmd *cobra.Command, args []string) {
			runServer()
		},
	}

	secrets = []Secret {
		{
			certificateChain: `-----BEGIN CERTIFICATE-----
MIIDnzCCAoegAwIBAgIJAI3dmBBDwTQCMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU3Vubnl2YWxl
MQ4wDAYDVQQKDAVJc3RpbzENMAsGA1UECwwEVGVzdDEQMA4GA1UEAwwHUm9vdCBD
QTEiMCAGCSqGSIb3DQEJARYTdGVzdHJvb3RjYUBpc3Rpby5pbzAgFw0xODA1MDgx
OTQ5MjRaGA8yMTE4MDQxNDE5NDkyNFowWTELMAkGA1UEBhMCVVMxEzARBgNVBAgM
CkNhbGlmb3JuaWExEjAQBgNVBAcMCVN1bm55dmFsZTEOMAwGA1UECgwFSXN0aW8x
ETAPBgNVBAMMCElzdGlvIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAtqwOeCRGd9H91ieHQmDX0KR6RHEVHxN6X3VsL8RXu8GtaULP3IFmitbY2uLo
VpdB4JxuDmuIDYbktqheLYD4g55klq13OInlEMtLk/u2H0Fvz70HRjDFAfOqY8OT
Ijs2+iM1H5OFVNrKxSHao/wiqbU3ZOZHu7ts6jcLrh8O+P17KRREaP7mapH1cETD
y/wA3qgE42ARfbO/0DPX2VQJuTewk1NJWQVdCkE7VWYR6F5PMTyBChT3lsqHalrL
EQCT5Ytcio+KPO6Y1qstrbFv++FAMQrthKlVcuPc6meOpszPjNqSQNCXpA99R6sl
AEzTSxmEpQrMUMPToHT6NRxs1wIDAQABozUwMzALBgNVHQ8EBAMCAgQwDAYDVR0T
BAUwAwEB/zAWBgNVHREEDzANggtjYS5pc3Rpby5pbzANBgkqhkiG9w0BAQsFAAOC
AQEAGpB9V2K7fEYYxmatjQLuNw0s+vKa5JkJrJO3H6Y1LAdKTJ3k7Cpr15zouM6d
5KogHfFHXPI6MU2ZKiiE38UPQ5Ha4D2XeuAwN64cDyN2emDnQ0UFNm+r4DY47jd3
jHq8I3reVSXeqoHcL0ViuGJRY3lrk8nmEo15vP1stmo5bBdnSlASDDjEjh1FHeXL
/Ha465WYESLcL4ps/xrcXN4JtV1nDGJVGy4WmusL+5D9nHC53/srZczZX3By48+Y
hhZwPFxt/EVB0YISgMOnMHzmWmnNWRiDuI6eZxUx0L9B9sD4s7zrQYYQ1bV/CPYX
iwlodzJwNdfIBfD/AC/GdnaWow==
-----END CERTIFICATE-----`,
			privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtqwOeCRGd9H91ieHQmDX0KR6RHEVHxN6X3VsL8RXu8GtaULP
3IFmitbY2uLoVpdB4JxuDmuIDYbktqheLYD4g55klq13OInlEMtLk/u2H0Fvz70H
RjDFAfOqY8OTIjs2+iM1H5OFVNrKxSHao/wiqbU3ZOZHu7ts6jcLrh8O+P17KRRE
aP7mapH1cETDy/wA3qgE42ARfbO/0DPX2VQJuTewk1NJWQVdCkE7VWYR6F5PMTyB
ChT3lsqHalrLEQCT5Ytcio+KPO6Y1qstrbFv++FAMQrthKlVcuPc6meOpszPjNqS
QNCXpA99R6slAEzTSxmEpQrMUMPToHT6NRxs1wIDAQABAoIBADyw4YXNF5SLsjhK
ncfSASIS44SFxayzff7lNnKQW03IRWMpjYIHhBgw1Y+zv9m1G3ASyQYFeAh2ftqp
CdE4fljMcUMWkvu35OE1igC6qoGr7ggpF5eccHf7iurmeaXv4o4s0GOTUcMlhiUE
4G2HQcT8rlDZqY+X79HJRBovu3vBvCktYMmzCXugrudwFkpbi5Dd3sFuPiKrXndY
oDPtjU2cb7Cg9DO8PZwab7tGWaFjstwXhIOE636uLog9xM9EC3D2qp9QFOVkmCH4
t4MzUCHcbIXRcunlil2+CYIFPDylJL6bFlpfVhtNubdgC35bsSql+h1QgZMezpAY
ZK9p7nECgYEA4hMKOAac1pnlfsXjf3jzZuZLBPIV/WpNZNsAIL/4aErSL0C3woRx
hj8q4onA0BD078r8n9zh3x/el17B/f43FoDydSkONlcUKaayHYlIhB1ULHPIEDVG
zlXIpkSi4Qui+51sZLnxXcmPbCT4LUN5nkWkZRHRboaufBAx+SdDRdUCgYEAzto/
cyEJ9p+e9chHSWv17pfeBu87XROwFS66hyWcnA5qDThbpvFakOGdCeKMKCS2ALW5
LsLx+PvN/V94AoJaMDsR3b2CH+/+cLWMLKqAiZzkha/Jr9FRyFPFs2nkZVkeekc8
FMXMwvs16hbBs3KHizJ5UswrGzOKWlPdpfxMofsCgYAoost/bpDacicyNlfCHfeC
U3rAlNMnDeiDbGoFePwpoulM3REqwau2Obx3o9MokyOzxoTKJ2XiOVRFWR79jKhS
PzNVo9+OHPDe27vAW2DRfoQWyWj4oNrtU7YRTN0KHpFZMN6+7D1aYlSJV8vUNwCx
VktKb315pHPQkQiqhEgvUQKBgFYSTnCTgNfUV4qiCbetaqobG1H7XdI/DPfjd84g
gmgVP1+84bY3m53Jo1SnpfZWQD1PYHzqtVELRg12GjPBFdIX4jlIT8sGS/OON4Om
dtHMLPLL0LqN+N/Iq+0Z1OWvDZWH6qIiJC/F5AtB6NvIfkoXeJBRUGaDLcCkQQh+
UUzdAoGBAKnmA0y3Up9QAowB1F7vvP9B4GzJ3qI/YNAkBE5keQePz/utetTStV+j
xcvcLWv3ZSpjpXSNwOBfdjdQirYFZQZtcAf9JxBkr0HaQ7w7MLxLp06O0YglH1Su
XyPkmABFTunZEBnpCd9NFXgzM3jQGvSZJOj1n0ZALZ1BM9k54e62
-----END RSA PRIVATE KEY-----`,
		},
		{
			certificateChain: `-----BEGIN CERTIFICATE-----
MIIDDDCCAnWgAwIBAgIJAPOCjrJP13nQMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMQ0wCwYDVQQKEwRMeWZ0MRkwFwYDVQQLExBMeWZ0IEVuZ2luZWVyaW5nMRAw
DgYDVQQDEwdUZXN0IENBMB4XDTE3MDcwOTAxMzkzMloXDTE5MDcwOTAxMzkzMlow
ejELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xDTALBgNVBAoTBEx5ZnQxGTAXBgNVBAsTEEx5ZnQgRW5naW5l
ZXJpbmcxFDASBgNVBAMTC1Rlc3QgU2VydmVyMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQDARNUJMFkWF0E6mbdz/nkydVC4TU2SgR95vhJhWpG6xKkCNoXkJxNz
XOmFUUIXQyq7FnIWACYuMrE2KXnomeCGP9A6M21lumNseYSLX3/b+ao4E6gimm1/
Gp8C3FaoAs8Ep7VE+o2DMIfTIPJhFf6RBFPundGhEm8/gv+QObVhKQIDAQABo4Gd
MIGaMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUF
BwMCBggrBgEFBQcDATAeBgNVHREEFzAVghNzZXJ2ZXIxLmV4YW1wbGUuY29tMB0G
A1UdDgQWBBRCcUr8mIigWlR61OX/gmDY5vBV6jAfBgNVHSMEGDAWgBQ7eKRRTxaE
kxxIKHoMrSuWQcp9eTANBgkqhkiG9w0BAQsFAAOBgQAtn05e8U41heun5L7MKflv
tJM7w0whavdS8hLe63CxnS98Ap973mSiShKG+OxSJ0ClMWIZPy+KyC+T8yGIaynj
wEEuoSGRWmhzcMMnZWxqQyD95Fsx6mtdnq/DJxiYzmH76fALe/538j8pTcoygSGD
NWw1EW8TEwlFyuvCrlWQcg==
-----END CERTIFICATE-----`,
			privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDARNUJMFkWF0E6mbdz/nkydVC4TU2SgR95vhJhWpG6xKkCNoXk
JxNzXOmFUUIXQyq7FnIWACYuMrE2KXnomeCGP9A6M21lumNseYSLX3/b+ao4E6gi
mm1/Gp8C3FaoAs8Ep7VE+o2DMIfTIPJhFf6RBFPundGhEm8/gv+QObVhKQIDAQAB
AoGBAJM64kukC0QAUMHX/gRD5HkAHuzSvUknuXuXUincmeWEPMtmBwdb6OgZSPT+
8XYwx+L14Cz6tkIALXWFM0YrtyKfVdELRRs8dw5nenzK3wOeo/N/7XL4kwim4kV3
q817RO6NUN76vHOsvQMFsPlEfCZpOTIGJEJBI7eFLP0djOMlAkEA/yWEPfQoER/i
X6uNyXrU51A6gxyZg7rPNP0cxxRhDedtsJPNY6Tlu90v9SiTgQLUTp7BINH24t9a
MST1tmax+wJBAMDpeRy52q+sqLXI1C2oHPuXrXzeyp9pynV/9tsYL9+qoyP2XcEZ
DaI0tfXDJXOdYIaDnSfB50eqQUnaTmQjtCsCQGUFGaLd9K8zDJIMforzUzByl3gp
7q41XK0COk6oRvUWWFu9aWi2dS84mDBc7Gn8EMtAF/9CopmZDUC//XlGl9kCQQCr
6yWw8PywFHohzwEwUyLJIKpOnyoKGTiBsHGpXYvEk4hiEzwISzB4PutuQuRMfZM5
LW/Pr6FSn6shivjTi3ITAkACMTBczBQ+chMBcTXDqyqwccQOIhupxani9wfZhsrm
ZXbTTxnUZioQ2l/7IWa+K2O2NrWWT7b3KpCAob0bJsQz
-----END RSA PRIVATE KEY-----`,
		},
	}
)

func init() {
	flags := rootCmd.Flags()
	flags.StringVar(&opts.UdsPath, "uds-path", "", "Path to the unix domain socket")
}

func (s *SDSServer) BuildResponse() (*api.DiscoveryResponse, error) {
	elapsed := time.Since(s.previousRequestTime)

	tlsCertificate := &auth.TlsCertificate{
		CertificateChain: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{[]byte(secrets[0].certificateChain)},
		},
		PrivateKey: &core.DataSource{
			Specifier: &core.DataSource_InlineBytes{[]byte(secrets[0].privateKey)},
		},
	}

	if math.Floor(math.Mod(elapsed.Seconds()/10, 2)) == 1 {
		tlsCertificate = &auth.TlsCertificate{
			CertificateChain: &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{[]byte(secrets[1].certificateChain)},
			},
			PrivateKey: &core.DataSource{
				Specifier: &core.DataSource_InlineBytes{[]byte(secrets[1].privateKey)},
			},
		}
	}

	resources := make([]types.Any, 1)
	secret := &auth.Secret{
		Name: SecretName,
		Type: &auth.Secret_TlsCertificate{
			TlsCertificate: tlsCertificate,
		},
	}
	data, err := proto.Marshal(secret)
	if err != nil {
		errMessage := fmt.Sprintf("Generates invalid secret (%v)", err)
		return nil, fmt.Errorf(errMessage)
	}
	resources[0] = types.Any{
		TypeUrl: SecretTypeURL,
		Value:   data,
	}

	response := &api.DiscoveryResponse{
		Resources:   resources,
		TypeUrl:     SecretTypeURL,
		VersionInfo: s.version,
	}

	return response, nil
}

// FetchSecrets fetches the X.509 key/cert for a given workload whose identity
// can be derived from the UDS path where this call is received.
func (s *SDSServer) FetchSecrets(ctx context.Context, request *api.DiscoveryRequest) (*api.DiscoveryResponse, error) {

	response, err :=  s.BuildResponse()
	if err != nil {
		log.Errorf("%v", err);
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	return response, nil
}

// StreamSecrets is not supported.
func (s *SDSServer) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	response, err :=  s.BuildResponse()
	if err != nil {
		log.Errorf("%v", err);
		return status.Errorf(codes.Unimplemented, err.Error())
	}

	stream.Send(response)
	log.Infof("Stream responded at %v", time.Now())
	return nil;

	/*
	ticker := time.NewTicker(time.Second * 5)
	go func() {
		for ; true; <-ticker.C {
			response, err :=  s.BuildResponse()
			if err != nil {
				log.Errorf("%v", err);
				return;
			}

			stream.Send(response)
			log.Infof("Stream responded at %v", time.Now())
		}
	}()

	log.Info("Streaming response has started")
	select {} // wait forever
	return nil;
	*/
}

// RegisterUdsPath registers a path for Unix Domain Socket and has
// SDSServer's gRPC server listen on it.
func (s *SDSServer) RegisterUdsPath(udsPath, identity string) error {
	_, err := os.Stat(udsPath)
	if err == nil {
		return fmt.Errorf("UDS path %v already exists", udsPath)
	}

	listener, err := net.Listen("unix", udsPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %v", err)
	}

	log.Errorf("listener.Addr()=%s", listener.Addr().String())

	var opts []grpc.ServerOption
	udsServer := grpc.NewServer(opts...)
	sds.RegisterSecretDiscoveryServiceServer(udsServer, s)
	s.udsServerMap[udsPath] = &SecretServerInfo{
		identity: identity,
		server:   udsServer,
	}

	// grpcServer.Serve() is a blocking call, so run it in a goroutine.
	go func() {
		log.Infof("Starting GRPC server on UDS path: %s", udsPath)
		err := udsServer.Serve(listener)
		// grpcServer.Serve() always returns a non-nil error.
		log.Warnf("GRPC server returns an error: %v", err)
	}()

	return nil
}

// DeregisterUdsPath closes and removes the grpcServer instance serving UDS
func (s *SDSServer) DeregisterUdsPath(udsPath string) error {
	udsServer, ok := s.udsServerMap[udsPath]
	if !ok {
		return fmt.Errorf("udsPath is not registered: %s", udsPath)
	}

	udsServer.server.GracefulStop()
	delete(s.udsServerMap, udsPath)
	log.Infof("stopped the GRPC server on UDS path: %s", udsPath)

	return nil
}

// NewSDSServer creates the SDSServer that registers
// SecretDiscoveryServiceServer, a gRPC server.
func NewSDSServer() *SDSServer {
	s := &SDSServer{
		udsServerMap:           map[string]*SecretServerInfo{},
		version:                fmt.Sprintf("%v", time.Now().UnixNano()/int64(time.Millisecond)),
		previousRequestTime: time.Now(),
	}

	return s
}

func runServer() {
	server := NewSDSServer()
	server.RegisterUdsPath(opts.UdsPath, "");
	defer server.DeregisterUdsPath(opts.UdsPath)

	log.Info("istio CA has started")
	select {} // wait forever
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errora(err)
		os.Exit(-1)
	}
}
