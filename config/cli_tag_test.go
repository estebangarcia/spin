package config

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestParseCliTagOpts(t *testing.T) {

	optsA := ParseCliTagOpts("help=Help Message for A;visible")
	optsB := ParseCliTagOpts("help=Help Message for B")
	optsC := ParseCliTagOpts("")

	assert.Equal(t, CliTag{
		Help:   "Help Message for A",
		Hidden: false,
	}, optsA)

	assert.Equal(t, CliTag{
		Help:   "Help Message for B",
		Hidden: true,
	}, optsB)

	assert.Equal(t, CliTag{
		Help:   "",
		Hidden: true,
	}, optsC)

}

func TestGeneratePFlagsFromStruct(t *testing.T) {
	type Test struct {
		A string   `cli:"help=Help Message for A;visible"`
		B []string `cli:"help=Help Message for B"`
		C bool
		D *struct {
			E string
		}
	}

	pflags := GeneratePFlagsFromStruct(&Test{}, "")

	assert.NotNil(t, pflags)

	var flags []*pflag.Flag

	pflags.VisitAll(func(flag *pflag.Flag) {
		flags = append(flags, flag)
	})

	assert.Len(t, flags, 4)

	assert.Equal(t, "a", flags[0].Name)
	assert.Equal(t, "Help Message for A", flags[0].Usage)
	assert.Equal(t, false, flags[0].Hidden)

	assert.Equal(t, "b", flags[1].Name)
	assert.Equal(t, "Help Message for B", flags[1].Usage)
	assert.Equal(t, true, flags[1].Hidden)

	assert.Equal(t, "c", flags[2].Name)
	assert.Equal(t, "", flags[2].Usage)
	assert.Equal(t, true, flags[2].Hidden)

	assert.Equal(t, "d.e", flags[3].Name)
	assert.Equal(t, "", flags[3].Usage)
	assert.Equal(t, true, flags[3].Hidden)

}

func TestGeneratePFlagsFromStruct_two(t *testing.T) {
	type Test struct {
		A string   `cli:"help=Help Message for A;visible"`
		B []string `cli:"help=Help Message for B"`
		C bool
		D struct {
			E string
		}
	}

	pflags := GeneratePFlagsFromStruct(&Test{}, "")

	assert.NotNil(t, pflags)

	var flags []*pflag.Flag

	pflags.VisitAll(func(flag *pflag.Flag) {
		flags = append(flags, flag)
	})

	assert.Len(t, flags, 4)

	assert.Equal(t, "a", flags[0].Name)
	assert.Equal(t, "Help Message for A", flags[0].Usage)
	assert.Equal(t, false, flags[0].Hidden)

	assert.Equal(t, "b", flags[1].Name)
	assert.Equal(t, "Help Message for B", flags[1].Usage)
	assert.Equal(t, true, flags[1].Hidden)

	assert.Equal(t, "c", flags[2].Name)
	assert.Equal(t, "", flags[2].Usage)
	assert.Equal(t, true, flags[2].Hidden)

	assert.Equal(t, "d.e", flags[3].Name)
	assert.Equal(t, "", flags[3].Usage)
	assert.Equal(t, true, flags[3].Hidden)

}

func TestGeneratePFlagsFromStruct_three(t *testing.T) {
	type Test struct {
		A int
	}

	assert.Panics(t, func() { GeneratePFlagsFromStruct(&Test{}, "") })

}

func TestGeneratePFlagsFromStruct_four(t *testing.T) {
	type Test struct {
		D *struct {
			E struct {
				F string
			}
		}
	}

	pflags := GeneratePFlagsFromStruct(&Test{}, "")

	assert.NotNil(t, pflags)

	var flags []*pflag.Flag

	pflags.VisitAll(func(flag *pflag.Flag) {
		flags = append(flags, flag)
	})

	assert.Len(t, flags, 1)

	assert.Equal(t, "d.e.f", flags[0].Name)
	assert.Equal(t, "", flags[0].Usage)
	assert.Equal(t, true, flags[0].Hidden)

}
