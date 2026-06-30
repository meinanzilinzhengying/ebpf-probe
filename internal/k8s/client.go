// Copyright (c) 2026 CloudFlow Team

package k8s

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	v1 "k8s.io/api/core/v1"
)

// K8sClient K8s 客户端
type K8sClient struct {
	clientset    kubernetes.Interface
	config       *rest.Config
	nodeName     string
	namespace    string
	podInformer  cache.SharedIndexInformer
	nodeInformer cache.SharedIndexInformer
	mu           sync.RWMutex
	running      bool
	stopCh       chan struct{}
}

// PodInfo Pod 信息
type PodInfo struct {
	Name       string
	Namespace  string
	NodeName   string
	UID        string
	Labels     map[string]string
	Containers []ContainerInfo
}

// ContainerInfo 容器信息
type ContainerInfo struct {
	Name      string
	Image     string
	ContainerID string
}

// NodeInfo Node 信息
type NodeInfo struct {
	Name       string
	Labels     map[string]string
	Addresses  []v1.NodeAddress
	Conditions []v1.NodeCondition
}

// NewK8sClient 创建 K8s 客户端
func NewK8sClient(apiServer, tokenPath, nodeName, namespace string) (*K8sClient, error) {
	var config *rest.Config
	var err error

	// 尝试 InCluster 配置
	config, err = rest.InClusterConfig()
	if err != nil {
		log.Printf("Not running in cluster, trying kubeconfig: %v", err)
		
		// 尝试 kubeconfig
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		if _, err := os.Stat(kubeconfig); err == nil {
			config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
			if err != nil {
				return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
			}
		} else if apiServer != "" {
			// 使用指定的 API Server
			config = &rest.Config{
				Host: apiServer,
			}
			
			// 如果有 token 文件，读取 token
			if tokenPath != "" {
				token, err := os.ReadFile(tokenPath)
				if err != nil {
					return nil, fmt.Errorf("failed to read token: %w", err)
				}
				config.BearerToken = string(token)
			}
		} else {
			return nil, fmt.Errorf("no k8s config available")
		}
	}

	// 创建客户端
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	// 获取当前节点名称
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	return &K8sClient{
		clientset: clientset,
		config:    config,
		nodeName:  nodeName,
		namespace: namespace,
		stopCh:    make(chan struct{}),
	}, nil
}

// Start 启动 K8s 客户端
func (c *K8sClient) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	// 启动 Pod Informer
	if err := c.startPodInformer(ctx); err != nil {
		return fmt.Errorf("failed to start pod informer: %w", err)
	}

	// 启动 Node Informer
	if err := c.startNodeInformer(ctx); err != nil {
		return fmt.Errorf("failed to start node informer: %w", err)
	}

	c.running = true
	log.Printf("K8s client started, node: %s", c.nodeName)

	return nil
}

// startPodInformer 启动 Pod Informer
func (c *K8sClient) startPodInformer(ctx context.Context) error {
	// 创建 Pod Informer
	c.podInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (interface{}, error) {
				// 如果指定了 namespace，只监听该 namespace
				if c.namespace != "" {
					return c.clientset.CoreV1().Pods(c.namespace).List(ctx, options)
				}
				return c.clientset.CoreV1().Pods("").List(ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (cache.Watcher, error) {
				if c.namespace != "" {
					return c.clientset.CoreV1().Pods(c.namespace).Watch(ctx, options)
				}
				return c.clientset.CoreV1().Pods("").Watch(ctx, options)
			},
		},
		&v1.Pod{},
		0,
		cache.Indexers{
			"node": func(obj interface{}) ([]string, error) {
				pod := obj.(*v1.Pod)
				return []string{pod.Spec.NodeName}, nil
			},
			"uid": func(obj interface{}) ([]string, error) {
				pod := obj.(*v1.Pod)
				return []string{string(pod.UID)}, nil
			},
		},
	)

	// 启动 informer
	go c.podInformer.Run(c.stopCh)

	// 等待缓存同步
	if !cache.WaitForCacheSync(ctx.Done(), c.podInformer.HasSynced) {
		return fmt.Errorf("failed to sync pod cache")
	}

	return nil
}

// startNodeInformer 启动 Node Informer
func (c *K8sClient) startNodeInformer(ctx context.Context) error {
	// 创建 Node Informer
	c.nodeInformer = cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (interface{}, error) {
				return c.clientset.CoreV1().Nodes().List(ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (cache.Watcher, error) {
				return c.clientset.CoreV1().Nodes().Watch(ctx, options)
			},
		},
		&v1.Node{},
		0,
		cache.Indexers{
			"name": func(obj interface{}) ([]string, error) {
				node := obj.(*v1.Node)
				return []string{node.Name}, nil
			},
		},
	)

	// 启动 informer
	go c.nodeInformer.Run(c.stopCh)

	// 等待缓存同步
	if !cache.WaitForCacheSync(ctx.Done(), c.nodeInformer.HasSynced) {
		return fmt.Errorf("failed to sync node cache")
	}

	return nil
}

// Stop 停止 K8s 客户端
func (c *K8sClient) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return
	}

	close(c.stopCh)
	c.running = false
	log.Printf("K8s client stopped")
}

// GetPodByPID 根据 PID 获取 Pod 信息
func (c *K8sClient) GetPodByPID(pid uint32) *PodInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.podInformer == nil {
		return nil
	}

	// 获取所有 Pod
	pods := c.podInformer.GetStore().List()
	
	for _, obj := range pods {
		pod := obj.(*v1.Pod)
		
		// 检查 Pod 是否在当前节点
		if pod.Spec.NodeName != c.nodeName {
			continue
		}

		// 检查 Pod 状态
		if pod.Status.Phase != v1.PodRunning {
			continue
		}

		// 遍历容器
		for _, containerStatus := range pod.Status.ContainerStatuses {
			// 这里需要通过 /proc/<pid>/cgroup 获取容器 ID
			// 简化处理：直接返回 Pod 信息
			return &PodInfo{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				NodeName:  pod.Spec.NodeName,
				UID:       string(pod.UID),
				Labels:    pod.Labels,
				Containers: []ContainerInfo{
					{
						Name:        containerStatus.Name,
						Image:       containerStatus.Image,
						ContainerID: containerStatus.ContainerID,
					},
				},
			}
		}
	}

	return nil
}

// GetPodByUID 根据 UID 获取 Pod 信息
func (c *K8sClient) GetPodByUID(uid string) *PodInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.podInformer == nil {
		return nil
	}

	// 通过索引获取
	objs, err := c.podInformer.GetIndexer().ByIndex("uid", uid)
	if err != nil || len(objs) == 0 {
		return nil
	}

	pod := objs[0].(*v1.Pod)

	return &PodInfo{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		NodeName:  pod.Spec.NodeName,
		UID:       string(pod.UID),
		Labels:    pod.Labels,
	}
}

// GetPodsByNode 获取指定节点的所有 Pod
func (c *K8sClient) GetPodsByNode(nodeName string) []*PodInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.podInformer == nil {
		return nil
	}

	// 通过索引获取
	objs, err := c.podInformer.GetIndexer().ByIndex("node", nodeName)
	if err != nil {
		return nil
	}

	var pods []*PodInfo
	for _, obj := range objs {
		pod := obj.(*v1.Pod)
		pods = append(pods, &PodInfo{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			NodeName:  pod.Spec.NodeName,
			UID:       string(pod.UID),
			Labels:    pod.Labels,
		})
	}

	return pods
}

// GetNodeInfo 获取当前节点信息
func (c *K8sClient) GetNodeInfo() *NodeInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.nodeInformer == nil {
		return nil
	}

	// 通过索引获取
	objs, err := c.nodeInformer.GetIndexer().ByIndex("name", c.nodeName)
	if err != nil || len(objs) == 0 {
		return nil
	}

	node := objs[0].(*v1.Node)

	return &NodeInfo{
		Name:       node.Name,
		Labels:     node.Labels,
		Addresses:  node.Status.Addresses,
		Conditions: node.Status.Conditions,
	}
}

// GetPodCount 获取 Pod 数量
func (c *K8sClient) GetPodCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.podInformer == nil {
		return 0
	}

	return c.podInformer.GetStore().Len()
}

// IsRunning 检查客户端是否运行
func (c *K8sClient) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.running
}

// GetServiceAccountToken 获取 ServiceAccount Token
func GetServiceAccountToken(tokenPath string) (string, error) {
	if tokenPath == "" {
		tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read token: %w", err)
	}

	return string(token), nil
}

// WaitForReady 等待客户端就绪
func (c *K8sClient) WaitForReady(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for k8s client ready")
		case <-ticker.C:
			if c.IsRunning() && c.podInformer.HasSynced() && c.nodeInformer.HasSynced() {
				return nil
			}
		}
	}
}
