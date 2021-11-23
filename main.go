package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/yaml.v2"
)

var (
	configFilePath = fmt.Sprintf("%s/.aws/roles", os.Getenv("HOME"))
	roleArnRe      = regexp.MustCompile(`^arn:aws:iam::(.+):role/([^/]+)(/.+)?$`)
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <role> [<command> <args...>]\n", os.Args[0])
	flag.PrintDefaults()
}

func init() {
	flag.Usage = usage
}

func defaultFormat() string {
	var shell = os.Getenv("SHELL")

	switch runtime.GOOS {
	case "windows":
		if os.Getenv("SHELL") == "" {
			return "powershell"
		}
		fallthrough
	default:
		if strings.HasSuffix(shell, "fish") {
			return "fish"
		}
		return "bash"
	}
}

func main() {
	var (
		duration = flag.Duration("duration", time.Hour, "The duration that the credentials will be valid for.")
		format   = flag.String("format", defaultFormat(), "Format can be 'bash' or 'powershell'.")
	)
	flag.Parse()
	argv := flag.Args()

	role := ""
	var args []string
	if len(argv) < 1 {
		role = autoDetectAccount()
		// flag.Usage()
		// os.Exit(1)
	} else {
		role = argv[0]
		args = argv[1:]
	}

	stscreds.DefaultDuration = *duration

	// Load credentials from configFilePath if it exists, else use regular AWS config
	var creds *credentials.Value
	var err error
	if roleArnRe.MatchString(role) {
		creds, err = assumeRole(role, "", *duration)
	} else if _, err = os.Stat(configFilePath); err == nil {
		fmt.Fprintf(os.Stderr, "WARNING: using deprecated role file (%s), switch to config file"+
			" (https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html)\n",
			configFilePath)
		config, err := loadConfig()
		must(err)

		roleConfig, ok := config[role]
		if !ok {
			must(fmt.Errorf("%s not in %s", role, configFilePath))
		}

		creds, err = assumeRole(roleConfig.Role, roleConfig.MFA, *duration)

		if err != nil {
			must(fmt.Errorf("ERROR assuming the role %s", err))
		}
	} else {
		creds, err = assumeProfile(role)
	}

	must(err)

	if len(args) == 0 {
		switch *format {
		case "powershell":
			printPowerShellCredentials(role, creds)
		case "bash":
			printCredentials(role, creds)
		case "fish":
			printFishCredentials(role, creds)
		default:
			flag.Usage()
			os.Exit(1)
		}
		return
	}

	err = execWithCredentials(role, args, creds)
	must(err)
}

func execWithCredentials(role string, argv []string, creds *credentials.Value) error {
	argv0, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}

	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	os.Setenv("AWS_SECURITY_TOKEN", creds.SessionToken)
	os.Setenv("ASSUMED_ROLE", role)

	env := os.Environ()
	return syscall.Exec(argv0, argv, env)
}

// printCredentials prints the credentials in a way that can easily be sourced
// with bash.
func printCredentials(role string, creds *credentials.Value) {
	fmt.Printf("export AWS_ACCESS_KEY_ID=\"%s\"\n", creds.AccessKeyID)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=\"%s\"\n", creds.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("export AWS_SECURITY_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("export ASSUMED_ROLE=\"%s\"\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# eval $(%s)\n", strings.Join(os.Args, " "))
}

// printFishCredentials prints the credentials in a way that can easily be sourced
// with fish.
func printFishCredentials(role string, creds *credentials.Value) {
	fmt.Printf("set -gx AWS_ACCESS_KEY_ID \"%s\";\n", creds.AccessKeyID)
	fmt.Printf("set -gx AWS_SECRET_ACCESS_KEY \"%s\";\n", creds.SecretAccessKey)
	fmt.Printf("set -gx AWS_SESSION_TOKEN \"%s\";\n", creds.SessionToken)
	fmt.Printf("set -gx AWS_SECURITY_TOKEN \"%s\";\n", creds.SessionToken)
	fmt.Printf("set -gx ASSUMED_ROLE \"%s\";\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# eval (%s)\n", strings.Join(os.Args, " "))
}

// printPowerShellCredentials prints the credentials in a way that can easily be sourced
// with Windows powershell using Invoke-Expression.
func printPowerShellCredentials(role string, creds *credentials.Value) {
	fmt.Printf("$env:AWS_ACCESS_KEY_ID=\"%s\"\n", creds.AccessKeyID)
	fmt.Printf("$env:AWS_SECRET_ACCESS_KEY=\"%s\"\n", creds.SecretAccessKey)
	fmt.Printf("$env:AWS_SESSION_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("$env:AWS_SECURITY_TOKEN=\"%s\"\n", creds.SessionToken)
	fmt.Printf("$env:ASSUMED_ROLE=\"%s\"\n", role)
	fmt.Printf("# Run this to configure your shell:\n")
	fmt.Printf("# %s | Invoke-Expression \n", strings.Join(os.Args, " "))
}

// assumeProfile assumes the named profile which must exist in ~/.aws/config
// (https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html) and returns the temporary STS
// credentials.
func assumeProfile(profile string) (*credentials.Value, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Profile:                 profile,
		SharedConfigState:       session.SharedConfigEnable,
		AssumeRoleTokenProvider: readTokenCode,
	}))

	creds, err := sess.Config.Credentials.Get()
	if err != nil {
		return nil, err
	}
	return &creds, nil
}

// assumeRole assumes the given role and returns the temporary STS credentials.
func assumeRole(role, mfa string, duration time.Duration) (*credentials.Value, error) {
	sess := session.Must(session.NewSession())

	svc := sts.New(sess)

	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(role),
		RoleSessionName: aws.String("cli"),
		DurationSeconds: aws.Int64(int64(duration / time.Second)),
	}
	if mfa != "" {
		params.SerialNumber = aws.String(mfa)
		token, err := readTokenCode()
		if err != nil {
			return nil, err
		}
		params.TokenCode = aws.String(token)
	}

	resp, err := svc.AssumeRole(params)

	if err != nil {
		return nil, err
	}

	var creds credentials.Value
	creds.AccessKeyID = *resp.Credentials.AccessKeyId
	creds.SecretAccessKey = *resp.Credentials.SecretAccessKey
	creds.SessionToken = *resp.Credentials.SessionToken

	return &creds, nil
}

type roleConfig struct {
	Role string `yaml:"role"`
	MFA  string `yaml:"mfa"`
}

type config map[string]roleConfig

// readTokenCode reads the MFA token from Stdin.
func readTokenCode() (string, error) {
	r := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "MFA code: ")
	text, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

// loadConfig loads the ~/.aws/roles file.
func loadConfig() (config, error) {
	raw, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	roleConfig := make(config)
	return roleConfig, yaml.Unmarshal(raw, &roleConfig)
}

func must(err error) {
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			// Errors are already on Stderr.
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func autoDetectAccount() string {
	basePath := "/Users"
	fileName := "common.tfvars"
	currentPath, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	targetPath := currentPath

	foundPath := foundCommonVarsFile(basePath, targetPath, fileName)
	account := ""
	if foundPath != "" {
		account = findAccountIdInCommonVars(foundPath, fileName)
	} else {
		panic("Not AWS account found in common.tfvars")
	}

	return findProfileInAWSConfig(account, currentPath)
}

func foundCommonVarsFile(basePath string, targetPath string, fileName string) string {
	foundPath := ""
	for {
		rel, _ := filepath.Rel(basePath, targetPath)

		// Exit the loop once we reach the basePath.
		if rel == "." {
			break
		}

		filepath.WalkDir(targetPath, func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && info.Name() == fileName {
				foundPath = targetPath
				return nil
			}
			return nil
		})

		if foundPath != "" {
			break
		}
		// Going up!
		targetPath += "/.."
	}

	return foundPath
}

func findAccountIdInCommonVars(targetPath string, fileName string) string {
	account := ""
	dat, err := ioutil.ReadFile(fmt.Sprintf("%v/%v", targetPath, fileName))
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(dat)))

	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "account") {
			account = strings.Split(scanner.Text(), "\"")[1]
		}
	}
	return account
}

func findProfileInAWSConfig(account string, currentPath string) string {

	splittedPath := strings.Split(currentPath, "/")
	awsConfigPath := "/" + splittedPath[1] + "/" + splittedPath[2] + "/.aws"
	awsConfigFileName := "config"

	dat, err := ioutil.ReadFile(fmt.Sprintf("%v/%v", awsConfigPath, awsConfigFileName))
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(dat)))

	var profilesLinesFound []int
	line := 1
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), account) {
			if strings.Contains(scanner.Text(), "role_arn") {
				profilesLinesFound = append(profilesLinesFound, line-1)
			}
		}
		line++
	}

	scanner2 := bufio.NewScanner(strings.NewReader(string(dat)))
	line = 1
	var profilesFound []string
	for scanner2.Scan() {
		if intInSlice(line, profilesLinesFound) {
			splittedProfile := strings.Split(scanner2.Text(), " ")
			profilesFound = append(profilesFound, splittedProfile[1][:len(splittedProfile[1])-1])
		}
		line++
	}
	fmt.Printf("\nprofilesFound = %v", profilesFound)

	if len(profilesFound) > 1 {
		// DO SOMETHING
		return confirmProfile(profilesFound)
	} else {
		return profilesFound[0]
	}

}

func intInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func confirmProfile(foundProfiles []string) string {
	fmt.Printf("I have found more than one profile available for this account, please choose one:")
	for i, profile := range foundProfiles {
		fmt.Printf("\n(%d) %s", i, profile)
	}
	fmt.Print("\nOr empty to abort\n")
	var option string

	// Taking input from user
	fmt.Scanln(&option)
	selectedOption, err := strconv.Atoi(option)
	if err != nil {
		panic(err)
	}

	return foundProfiles[selectedOption]
}
