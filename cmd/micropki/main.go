package main

import (
	"fmt"
	"os"

	"micropki/internal/ca"

	"github.com/spf13/cobra"
)

var (
	subject        string
	keyType        string
	keySize        int
	passphraseFile string
	outDir         string
	validityDays   int
	logFile        string
	force          bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "micropki",
		Short: "MicroPKI - Minimal PKI Tool",
	}

	caCmd := &cobra.Command{
		Use:   "ca",
		Short: "CA operations",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Root CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			return ca.InitCA(
				subject,
				keyType,
				keySize,
				passphraseFile,
				outDir,
				validityDays,
				logFile,
				force,
			)
		},
	}

	// Настройка флагов для 'ca init'
	initCmd.Flags().StringVar(&subject, "subject", "", "Distinguished Name (e.g., /CN=Root CA)")
	initCmd.Flags().StringVar(&keyType, "key-type", "rsa", "Key type (rsa or ecc)")
	initCmd.Flags().IntVar(&keySize, "key-size", 4096, "Key size (RSA: 4096, ECC: 384)")
	initCmd.Flags().StringVar(&passphraseFile, "passphrase-file", "", "File containing passphrase")
	initCmd.Flags().StringVar(&outDir, "out-dir", "./pki", "Output directory")
	initCmd.Flags().IntVar(&validityDays, "validity-days", 3650, "Validity period in days")
	initCmd.Flags().StringVar(&logFile, "log-file", "", "Optional log file path")
	initCmd.Flags().BoolVar(&force, "force", false, "Force overwrite existing files")

	initCmd.MarkFlagRequired("subject")
	initCmd.MarkFlagRequired("passphrase-file")

	caCmd.AddCommand(initCmd)
	rootCmd.AddCommand(caCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
