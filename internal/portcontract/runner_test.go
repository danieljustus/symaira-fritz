package portcontract

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestIsolatedEnvironment(t *testing.T) {
	t.Setenv("SYMFRITZ_TEST_SECRET", "not-a-real-secret")
	home := t.TempDir()
	env, err := IsolatedEnvironment(home)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "SYMFRITZ_TEST_SECRET=") {
		t.Fatal("isolated environment retained a SYMFRITZ variable")
	}
	for _, expected := range []string{
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + home + string(os.PathSeparator) + "config",
		"LC_ALL=C",
		"TZ=UTC",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("isolated environment missing %q", expected)
		}
	}
}

func TestRunCapturesOutputAndExitCode(t *testing.T) {
	t.Setenv("PORTCONTRACT_HELPER", "exit")
	result, err := Run(os.Args[0], []string{"-test.run=^TestHelperProcess$"}, t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 9 || string(result.Stdout) != "stdout\n" || string(result.Stderr) != "stderr\n" || result.TimedOut {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunKillsTimedOutProcess(t *testing.T) {
	t.Setenv("PORTCONTRACT_HELPER", "sleep")
	result, err := Run(os.Args[0], []string{"-test.run=^TestHelperProcess$"}, t.TempDir(), 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut {
		t.Fatalf("result = %+v, want timeout", result)
	}
}

func TestHelperProcess(t *testing.T) {
	switch os.Getenv("PORTCONTRACT_HELPER") {
	case "exit":
		_, _ = os.Stdout.WriteString("stdout\n")
		_, _ = os.Stderr.WriteString("stderr\n")
		os.Exit(9)
	case "sleep":
		time.Sleep(10 * time.Second)
	}
}
