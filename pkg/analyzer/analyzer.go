package analyzer

import (
    "context"
    "flag"
    "fmt"
    "path/filepath"
    "strings"
    "time"

    "github.com/briandowns/spinner"
    "github.com/fatih/color"
    rbacv1 "k8s.io/api/rbac/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/util/homedir"

    "KPatrol/pkg/config"
)

func AnalyzeClusterPermissions(clientset *kubernetes.Clientset, cfg *config.Config) {
    s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)

    for _, perm := range cfg.SensitivePermissions {
        s.Suffix = fmt.Sprintf(" Analyzing Rule: %s", perm.Name)
        s.Start()

        roleBindings, _ := clientset.RbacV1().RoleBindings("").List(context.TODO(), metav1.ListOptions{})
        clusterRoleBindings, _ := clientset.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})

        data := [][]string{}
        processRoleBindings(roleBindings.Items, clientset, cfg, &data, perm)
        processClusterRoleBindings(clusterRoleBindings.Items, clientset, cfg, &data, perm)

        s.Stop()

        if len(data) > 0 {
            printRuleOutput(perm.Name, perm.Impact, data, clientset)
        } else {
            printNoSensitivePermissionsFound(perm.Name)
        }
    }
}


func processRoleBindings(bindings []rbacv1.RoleBinding, clientset *kubernetes.Clientset, cfg *config.Config, data *[][]string, perm config.PermissionRule) {
    for _, binding := range bindings {
        rules := getRulesFromRole(binding.RoleRef.Name, binding.Namespace, clientset, true)
        processData(binding.Subjects, rules, binding.Namespace, cfg, data, false, perm)
    }
}


func processClusterRoleBindings(bindings []rbacv1.ClusterRoleBinding, clientset *kubernetes.Clientset, cfg *config.Config, data *[][]string, perm config.PermissionRule) {
    for _, binding := range bindings {
        rules := getRulesFromRole(binding.RoleRef.Name, "", clientset, false)
        processData(binding.Subjects, rules, "", cfg, data, true, perm)
    }
}


func processData(subjects []rbacv1.Subject, rules []rbacv1.PolicyRule, namespace string, cfg *config.Config, data *[][]string, clusterWide bool, perm config.PermissionRule) {
    for _, subject := range subjects {
        for _, rule := range rules {
            if isSensitive(rule, perm) && !isException(subject, namespace, rule, cfg) {
                resources := fmt.Sprintf("%s - %s", strings.Join(rule.Resources, ", "), strings.Join(rule.Verbs, ", "))
                namespaceAccess := namespace
                if clusterWide {
                    namespaceAccess = "*"
                }
                *data = append(*data, []string{subject.Kind, subject.Name, perm.Name, namespaceAccess, perm.Impact, resources})
            }
        }
    }
}


func printRuleOutput(ruleName, impact string, data [][]string, clientset *kubernetes.Clientset) {
    green := color.New(color.FgGreen).SprintFunc()
    red := color.New(color.FgRed).SprintFunc()
    yellow := color.New(color.FgYellow).SprintFunc()
    blue := color.New(color.FgBlue).SprintFunc()

    fmt.Println(green(fmt.Sprintf("Enumerating Rule: %s", ruleName)))
    fmt.Println(yellow(fmt.Sprintf("Impact: %s", impact)))
    fmt.Println("Found Users/Service Accounts:")

    found := false
    for _, v := range data {
        kind := v[0]
        name := v[1]
        namespaceAccess := v[3]
        permissions := v[5]

        fmt.Print(red(fmt.Sprintf("  - %s: %s", kind, name)))
        if kind == "ServiceAccount" {
            var podNames string
            if namespaceAccess == "*" {
                podNames = getServiceAccountPodsAllNamespaces(clientset, name)
            } else {
                podNames = getServiceAccountPods(clientset, name, namespaceAccess)
            }

            if len(podNames) > 0 {
                fmt.Println(blue(fmt.Sprintf(" (mounted in pods: %s)", podNames)))
            } else {
                fmt.Println()
            }
        } else {
            fmt.Println()
        }
        fmt.Println(fmt.Sprintf("    Permissions: %s", permissions))
        fmt.Println(fmt.Sprintf("    Namespace Access: %s", namespaceAccess))
        found = true
    }

    if !found {
        fmt.Println(red("  No sensitive permissions found for this rule."))
    }
    fmt.Println(green("---"))
}


func printNoSensitivePermissionsFound(ruleName string) {
    green := color.New(color.FgGreen).SprintFunc()
    red := color.New(color.FgRed).SprintFunc()

    fmt.Println(green(fmt.Sprintf("Enumerating Rule: %s", ruleName)))
    fmt.Println(red("  No sensitive permissions found for this rule."))
    fmt.Println(green("---"))
}


func getRulesFromRole(roleName, namespace string, clientset *kubernetes.Clientset, isRole bool) []rbacv1.PolicyRule {
    var rules []rbacv1.PolicyRule
    if isRole {
        role, err := clientset.RbacV1().Roles(namespace).Get(context.TODO(), roleName, metav1.GetOptions{})
        if err == nil {
            rules = role.Rules
        }
    } else {
        clusterRole, err := clientset.RbacV1().ClusterRoles().Get(context.TODO(), roleName, metav1.GetOptions{})
        if err == nil {
            rules = clusterRole.Rules
        }
    }
    return rules
}

func isSensitive(rule rbacv1.PolicyRule, perm config.PermissionRule) bool {
    apiGroupMatch := len(perm.ApiGroups) == 0 || intersects(perm.ApiGroups, rule.APIGroups)
    for _, verb := range rule.Verbs {
        for _, pVerb := range perm.Verbs {
            if verb == pVerb && apiGroupMatch {
                for _, resource := range rule.Resources {
                    if contains(perm.Resources, resource) || perm.Resources[0] == "*" {
                        return true
                    }
                }
            }
        }
    }
    return false
}


func isException(subject rbacv1.Subject, namespace string, rule rbacv1.PolicyRule, cfg *config.Config) bool {
    for _, perm := range cfg.SensitivePermissions {
        if contains(perm.Exceptions.Users, subject.Name) ||
            contains(perm.Exceptions.ServiceAccounts, subject.Name) ||
            contains(perm.Exceptions.Namespaces, namespace) ||
            intersects(perm.Exceptions.Resources, rule.Resources) ||
            intersects(perm.Exceptions.Actions, rule.Verbs) {
            return true
        }
    }
    return false
}


func getServiceAccountPodsAllNamespaces(clientset *kubernetes.Clientset, saName string) string {
    namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return ""
    }

    var allPodNames []string
    for _, ns := range namespaces.Items {
        podNames := getServiceAccountPods(clientset, saName, ns.Name)
        if len(podNames) > 0 {
            allPodNames = append(allPodNames, fmt.Sprintf("%s: %s", ns.Name, podNames))
        }
    }
    return strings.Join(allPodNames, "; ")
}


func getServiceAccountPods(clientset *kubernetes.Clientset, saName, namespace string) string {
    pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return ""
    }

    var podNames []string
    for _, pod := range pods.Items {
        if pod.Spec.ServiceAccountName == saName {
            podNames = append(podNames, pod.Name)
        }
    }
    return strings.Join(podNames, ", ")
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}


func intersects(slice1, slice2 []string) bool {
    set := make(map[string]struct{})
    for _, item := range slice1 {
        set[item] = struct{}{}
    }
    for _, item := range slice2 {
        if _, found := set[item]; found {
            return true
        }
    }
    return false
}


func GetClientSet() (*kubernetes.Clientset, error) {
    var kubeconfig string
    if home := homedir.HomeDir(); home != "" {
        kubeconfig = filepath.Join(home, ".kube", "config")
    } else {
        kubeconfig = ""
    }

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


func main() {
    configPath := flag.String("config", "", "path to the config file")
    flag.Parse()
    if *configPath == "" {
        fmt.Println("Please specify the config file path using the -config flag.")
        return
    }

    cfg, err := config.LoadConfig(*configPath)
    if err != nil {
        fmt.Printf("Error loading configuration: %v\n", err)
        return
    }

    clientset, err := GetClientSet()
    if err != nil {
        fmt.Printf("Error creating Kubernetes client: %v\n", err)
        return
    }

    AnalyzeClusterPermissions(clientset, cfg)
}

