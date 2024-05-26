package config

import (
    "github.com/spf13/viper"
)


type Config struct {
    SensitivePermissions []PermissionRule `yaml:"sensitivePermissions"`
}

type PermissionRule struct {
    Name        string   `yaml:"name"`
    Resources   []string `yaml:"resources"`
    Verbs       []string `yaml:"verbs"`
    Impact      string   `yaml:"impact"`
    ApiGroups   []string `yaml:"apiGroups"`
    Exceptions  struct {
        Users            []string `yaml:"users"`
        ServiceAccounts  []string `yaml:"serviceAccounts"`
        Namespaces       []string `yaml:"namespaces"`
        Resources        []string `yaml:"resources"`
        Actions          []string `yaml:"actions"`
    } `yaml:"exceptions"`
}


type Exception struct {
    Users           []string `mapstructure:"users"`
    ServiceAccounts []string `mapstructure:"serviceAccounts"`
    Namespaces      []string `mapstructure:"namespaces"`
    Resources       []string `mapstructure:"resources"`
    Actions         []string `mapstructure:"actions"`
}

func LoadConfig(fullPath string) (*Config, error) {
    viper.SetConfigFile(fullPath)

    if err := viper.ReadInConfig(); err != nil {
        return nil, err
    }

    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, err
    }

    return &config, nil
}

