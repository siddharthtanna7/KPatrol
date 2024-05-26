package client

import (
    "flag"
    "os"
    "path/filepath"

    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
)

func GetClientset() (*kubernetes.Clientset, error) {
    var kubeconfig string
    if home := os.Getenv("HOME"); home != "" {
        kubeconfig = filepath.Join(home, ".kube", "config")
    }

    if envKubeConfig := os.Getenv("KUBECONFIG"); envKubeConfig != "" {
        kubeconfig = envKubeConfig
    }

    flag.StringVar(&kubeconfig, "kubeconfig", kubeconfig, "path to the kubeconfig file")
    flag.Parse()

    config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
    if err != nil {
        return nil, err
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, err
    }

    return clientset, nil
}

