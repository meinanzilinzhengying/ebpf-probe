package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// CloudPlatform 云平台类型
type CloudPlatform int

const (
	CloudNone CloudPlatform = iota
	CloudAliyun
	CloudHuawei
	CloudAWS
	CloudGCP
	CloudAzure
)

// CloudMetadata 云平台元数据
type CloudMetadata struct {
	Platform       CloudPlatform
	InstanceID     string
	InstanceType   string
	Region         string
	Zone           string
	VPCID          string
	SubnetID       string
	PrivateIP      string
	PublicIP       string
	Hostname       string
	ImageID        string
}

// CloudMetadataCollector 云平台元数据采集器
type CloudMetadataCollector struct {
	platform CloudPlatform
	metadata *CloudMetadata
	client   *http.Client
	interval time.Duration
	stopCh   chan struct{}
}

// NewCloudMetadataCollector 创建云平台元数据采集器
func NewCloudMetadataCollector() *CloudMetadataCollector {
	return &CloudMetadataCollector{
		client: &http.Client{Timeout: 2 * time.Second},
		stopCh: make(chan struct{}),
	}
}

// Name 返回采集器名称
func (c *CloudMetadataCollector) Name() string {
	return "cloud_metadata"
}

// Category 返回采集器分类
func (c *CloudMetadataCollector) Category() string {
	return "platform"
}

// Init 初始化采集器
func (c *CloudMetadataCollector) Init() error {
	c.detectPlatform()
	if c.platform == CloudNone {
		log.Printf("cloud_metadata: no cloud platform detected")
		return nil
	}
	return nil
}

func (c *CloudMetadataCollector) detectPlatform() {
	// 检测阿里云
	if c.detectAliyun() {
		c.platform = CloudAliyun
		return
	}
	// 检测华为云
	if c.detectHuawei() {
		c.platform = CloudHuawei
		return
	}
	// 检测 AWS
	if c.detectAWS() {
		c.platform = CloudAWS
		return
	}
	// 检测 GCP
	if c.detectGCP() {
		c.platform = CloudGCP
		return
	}
	// 检测 Azure
	if c.detectAzure() {
		c.platform = CloudAzure
		return
	}
}

func (c *CloudMetadataCollector) detectAliyun() bool {
	resp, err := c.client.Get("http://100.100.100.200/latest/meta-data/instance-id")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (c *CloudMetadataCollector) detectHuawei() bool {
	resp, err := c.client.Get("http://169.254.169.254/openstack/latest/meta_data.json")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (c *CloudMetadataCollector) detectAWS() bool {
	resp, err := c.client.Get("http://169.254.169.254/latest/meta-data/instance-id")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (c *CloudMetadataCollector) detectGCP() bool {
	resp, err := c.client.Get("http://metadata.google.internal/computeMetadata/v1/instance/id")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.Header.Get("Metadata-Flavor") == "Google"
}

func (c *CloudMetadataCollector) detectAzure() bool {
	resp, err := c.client.Get("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.Header.Get("Metadata") == "true"
}

// Collect 采集云平台元数据
func (c *CloudMetadataCollector) Collect() (*CloudMetadata, error) {
	switch c.platform {
	case CloudAliyun:
		return c.collectAliyun()
	case CloudHuawei:
		return c.collectHuawei()
	case CloudAWS:
		return c.collectAWS()
	case CloudGCP:
		return c.collectGCP()
	case CloudAzure:
		return c.collectAzure()
	default:
		return nil, fmt.Errorf("no cloud platform detected")
	}
}

func (c *CloudMetadataCollector) collectAliyun() (*CloudMetadata, error) {
	m := &CloudMetadata{Platform: CloudAliyun}
	base := "http://100.100.100.200/latest/meta-data"

	m.InstanceID = c.fetch(base + "/instance-id")
	m.InstanceType = c.fetch(base + "/instance-type")
	m.Region = c.fetch(base + "/region-id")
	m.Zone = c.fetch(base + "/zone-id")
	m.VPCID = c.fetch(base + "/vpc-id")
	m.SubnetID = c.fetch(base + "/vswitch-id")
	m.PrivateIP = c.fetch(base + "/private-ipv4")
	m.PublicIP = c.fetch(base + "/eipAddress")
	m.Hostname = c.fetch(base + "/hostname")
	m.ImageID = c.fetch(base + "/image-id")

	return m, nil
}

func (c *CloudMetadataCollector) collectHuawei() (*CloudMetadata, error) {
	m := &CloudMetadata{Platform: CloudHuawei}
	base := "http://169.254.169.254/openstack/latest"

	data := c.fetch(base + "/meta_data.json")
	if data != "" {
		var meta map[string]interface{}
		json.Unmarshal([]byte(data), &meta)
		if v, ok := meta["instance-id"].(string); ok {
			m.InstanceID = v
		}
		if v, ok := meta["hostname"].(string); ok {
			m.Hostname = v
		}
	}

	m.Region = c.fetch(base + "/region")
	m.PrivateIP = c.fetch(base + "/local-ipv4")
	m.ImageID = c.fetch(base + "/image_id")

	return m, nil
}

func (c *CloudMetadataCollector) collectAWS() (*CloudMetadata, error) {
	m := &CloudMetadata{Platform: CloudAWS}
	base := "http://169.254.169.254/latest/meta-data"

	m.InstanceID = c.fetch(base + "/instance-id")
	m.InstanceType = c.fetch(base + "/instance-type")
	m.Region = c.fetch(base + "/placement/region")
	m.Zone = c.fetch(base + "/placement/availability-zone")
	m.PrivateIP = c.fetch(base + "/local-ipv4")
	m.PublicIP = c.fetch(base + "/public-ipv4")
	m.Hostname = c.fetch(base + "/local-hostname")
	m.ImageID = c.fetch(base + "/ami-id")

	return m, nil
}

func (c *CloudMetadataCollector) collectGCP() (*CloudMetadata, error) {
	m := &CloudMetadata{Platform: CloudGCP}
	base := "http://metadata.google.internal/computeMetadata/v1"

	header := http.Header{"Metadata-Flavor": []string{"Google"}}

	m.InstanceID = c.fetchWithHeader(base+"/instance/id", header)
	m.InstanceType = c.fetchWithHeader(base+"/instance/machine-type", header)
	m.Region = c.fetchWithHeader(base+"/instance/zone", header)
	m.PrivateIP = c.fetchWithHeader(base+"/instance/network-interface/0/ip", header)
	m.Hostname = c.fetchWithHeader(base+"/instance/hostname", header)
	m.ImageID = c.fetchWithHeader(base+"/instance/image", header)

	return m, nil
}

func (c *CloudMetadataCollector) collectAzure() (*CloudMetadata, error) {
	m := &CloudMetadata{Platform: CloudAzure}
	base := "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

	header := http.Header{"Metadata": []string{"true"}}
	data := c.fetchWithHeader(base, header)
	if data != "" {
		var meta map[string]interface{}
		json.Unmarshal([]byte(data), &meta)
		if v, ok := meta["instanceId"].(string); ok {
			m.InstanceID = v
		}
		if v, ok := meta["name"].(string); ok {
			m.Hostname = v
		}
	}

	return m, nil
}

func (c *CloudMetadataCollector) fetch(url string) string {
	return c.fetchWithHeader(url, nil)
}

func (c *CloudMetadataCollector) fetchWithHeader(url string, header http.Header) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	if header != nil {
		req.Header = header
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(body)
}

// Start 启动采集器
func (c *CloudMetadataCollector) Start() {
	metadata, err := c.Collect()
	if err != nil {
		log.Printf("cloud_metadata: collect failed: %v", err)
		return
	}
	c.metadata = metadata
	log.Printf("cloud_metadata: platform=%s, instance=%s", 
		getPlatformName(metadata.Platform), metadata.InstanceID)
}

func getPlatformName(p CloudPlatform) string {
	switch p {
	case CloudAliyun:
		return "aliyun"
	case CloudHuawei:
		return "huawei"
	case CloudAWS:
		return "aws"
	case CloudGCP:
		return "gcp"
	case CloudAzure:
		return "azure"
	default:
		return "unknown"
	}
}

// Stop 停止采集器
func (c *CloudMetadataCollector) Stop() {
	close(c.stopCh)
}

// GetMetadata 获取元数据
func (c *CloudMetadataCollector) GetMetadata() *CloudMetadata {
	return c.metadata
}
