package main

import (
    "flag"
    "fmt"
    "KPatrol/pkg/config"
    "KPatrol/pkg/client"
    "KPatrol/pkg/analyzer"
)

func main() {
    // Define a string flag with a default value and a short description.
    configPath := flag.String("config", "", "path to the config file")
    flag.Parse()

    // Check if the config path was provided.
    if *configPath == "" {
        fmt.Println("Please specify the config file path using the -config flag.")
        return
    }

    // Load configuration.
    cfg, err := config.LoadConfig(*configPath)
    if err != nil {
        fmt.Printf("Error loading configuration: %v\n", err)
        return
    }

    // Setup the Kubernetes client.
    clientset, err := client.GetClientset()
    if err != nil {
        fmt.Printf("Error setting up Kubernetes client: %v\n", err)
        return
    }

    // Analyze the permissions.
    analyzer.AnalyzeClusterPermissions(clientset, cfg)
}

