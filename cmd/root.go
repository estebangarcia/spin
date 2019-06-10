package cmd

import (
	"io"

	"github.com/estebangarcia/spin/config"

	"github.com/estebangarcia/spin/cmd/application"
	"github.com/estebangarcia/spin/cmd/pipeline"
	pipeline_template "github.com/estebangarcia/spin/cmd/pipeline-template"
	"github.com/estebangarcia/spin/cmd/project"
	"github.com/estebangarcia/spin/util"
	"github.com/estebangarcia/spin/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Execute(out io.Writer) error {
	cmd := NewCmdRoot(out)
	return cmd.Execute()
}

func NewCmdRoot(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
	}

	cobra.OnInitialize(initUI)
	cmd.PersistentFlags().String("config", "", "path to config file (default $HOME/.spin/config)")
	cmd.PersistentFlags().BoolP("quiet", "q", false, "squelch non-essential output")
	cmd.PersistentFlags().Bool("no-color", true, "disable color")
	cmd.PersistentFlags().String("output", "", "configure output formatting")

	flagSet := config.GeneratePFlagsFromStruct(&config.Config{}, "")
	cmd.PersistentFlags().AddFlagSet(flagSet)
	viper.BindPFlags(flagSet)

	// create subcommands
	cmd.AddCommand(application.NewApplicationCmd(out))
	cmd.AddCommand(pipeline.NewPipelineCmd(out))
	cmd.AddCommand(pipeline_template.NewPipelineTemplateCmd(out))
	cmd.AddCommand(project.NewProjectCmd(out))

	return cmd
}

func initUI() {
	quiet := viper.GetBool("quiet")
	nocolor := viper.GetBool("no-color")
	outputFormat := viper.GetString("output")
	util.InitUI(quiet, nocolor, outputFormat)
}
