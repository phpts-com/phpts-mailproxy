package main

import (
	"reflect"
	"testing"
)

func TestDaemonArgsDropsDaemonFlag(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{"去掉 -d", []string{"phpts-mailproxy", "-d", "-token", "abcd"}, []string{"-token", "abcd"}},
		{"去掉 -d=true", []string{"phpts-mailproxy", "-d=true", "-port", "3325"}, []string{"-port", "3325"}},
		{"其余参数原序保留", []string{"phpts-mailproxy", "-d", "-listen", "[::]", "-token", "abcd"}, []string{"-listen", "[::]", "-token", "abcd"}},
		{"无 -d 时原样", []string{"phpts-mailproxy", "-token", "abcd"}, []string{"-token", "abcd"}},
	}
	for _, c := range cases {
		got := daemonArgs(c.argv)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: daemonArgs(%v) = %v, want %v", c.name, c.argv, got, c.want)
		}
	}
}

func TestIsDaemonizedReadsEnvMark(t *testing.T) {
	t.Setenv(daemonEnv, "")
	if isDaemonized() {
		t.Fatal("无标记时不应判定为后台实例")
	}
	t.Setenv(daemonEnv, "1")
	if !isDaemonized() {
		t.Fatal("带标记时应判定为后台实例")
	}
}
