package config

import (
	"errors"
	"reflect"
	"strings"

	"github.com/spf13/pflag"
)

type CliTag struct {
	Help   string
	Name   string
	Hidden bool
}

func ParseCliTagOpts(tag string) CliTag {
	cliTagOpts := CliTag{
		Hidden: true,
	}

	if tag == "" {
		return cliTagOpts
	}

	args := strings.Split(tag, ";")
	for _, arg := range args {
		opt := arg
		value := ""
		if strings.Index(arg, "=") > 0 {
			opt = arg[0:strings.Index(arg, "=")]
			value = arg[strings.Index(arg, "=")+1 : len(arg)]
		}
		switch opt {
		case "help":
			cliTagOpts.Help = value
		case "visible":
			cliTagOpts.Hidden = false
		}
	}
	return cliTagOpts
}

// GeneratePFlagsFromStruct traverses the struct and generates a FlagSet based on it to be used by cobra
func GeneratePFlagsFromStruct(iface interface{}, prefix string) *pflag.FlagSet {
	set := pflag.NewFlagSet("dynamic_params", pflag.ContinueOnError)

	ifv := reflect.ValueOf(iface)
	if ifv.Kind() == reflect.Ptr {
		ifv = ifv.Elem()
	}

	ift := reflect.TypeOf(iface)
	if ift.Kind() == reflect.Ptr {
		ift = ift.Elem()
	}

	if ift.PkgPath() != "" && !strings.Contains(ift.PkgPath(), "spinnaker") {
		return set
	}

	if prefix != "" {
		prefix = prefix + "."
	}

	for i := 0; i < ift.NumField(); i++ {
		v := ifv.Field(i)

		switch v.Kind() {
		case reflect.Struct:
			set.AddFlagSet(GeneratePFlagsFromStruct(v.Interface(), prefix+ift.Field(i).Name))
		case reflect.Ptr:
			v.Set(reflect.New(v.Type().Elem()))
			set.AddFlagSet(GeneratePFlagsFromStruct(v.Interface(), prefix+ift.Field(i).Name))
		default:

			flagName := strings.ToLower(prefix + ift.Field(i).Name)

			cliTagOpts := ParseCliTagOpts(ift.Field(i).Tag.Get("cli"))

			if err := addFlagToSet(flagName, ift.Field(i).Type.String(), cliTagOpts, set); err != nil {

				// Type is not supported. Try to get the underlying type in case is not primitive
				err := addFlagToSet(flagName, reflect.TypeOf(v.Interface()).Kind().String(), cliTagOpts, set)
				if err != nil {
					panic(err)
				}

			}

		}
	}

	return set
}

func addFlagToSet(name string, flagType string, opts CliTag, set *pflag.FlagSet) error {
	switch flagType {
	case "string":
		set.String(name, "", opts.Help)
	case "bool":
		set.Bool(name, false, opts.Help)
	case "[]string":
		set.StringArray(name, []string{}, opts.Help)
	default:
		return errors.New("type not supported")
	}

	if opts.Hidden {
		set.MarkHidden(name)
	}

	return nil
}
