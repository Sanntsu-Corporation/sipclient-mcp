package calltester

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	pesqSampleRate      = 8000
	pesqPythonEnv       = "CVS_CALL_TESTER_PYTHON"
	pesqScorerScriptEnv = "CVS_CALL_TESTER_PESQ_SCORER"
)

type pesqScore struct {
	RawScore float64
	MOSLQO   float64
	Method   string
}

type pesqScriptResult struct {
	PESQRaw float64 `json:"pesq_raw"`
	MOSLQO  float64 `json:"mos_lqo"`
}

func scorePESQNB(referencePCMU []byte, degradedPCMU []byte) (pesqScore, error) {
	if len(referencePCMU) == 0 || len(degradedPCMU) == 0 {
		return pesqScore{}, fmt.Errorf("reference or degraded audio is empty")
	}

	referencePCM := decodePCMUToPCM16(referencePCMU)
	degradedPCM := decodePCMUToPCM16(degradedPCMU)

	refPath, err := writePCMTemp(referencePCM)
	if err != nil {
		return pesqScore{}, err
	}
	defer os.Remove(refPath)

	degPath, err := writePCMTemp(degradedPCM)
	if err != nil {
		return pesqScore{}, err
	}
	defer os.Remove(degPath)

	pythonPath, err := discoverPython()
	if err != nil {
		return pesqScore{}, err
	}
	scriptPath, err := discoverPESQScript()
	if err != nil {
		return pesqScore{}, err
	}

	cmd := exec.Command(pythonPath, scriptPath, refPath, degPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return pesqScore{}, fmt.Errorf("run pesq scorer: %w: %s", err, string(output))
	}

	var result pesqScriptResult
	if err := json.Unmarshal(output, &result); err != nil {
		return pesqScore{}, fmt.Errorf("decode pesq scorer output: %w", err)
	}
	if result.MOSLQO == 0 {
		result.MOSLQO = result.PESQRaw
	}
	if result.PESQRaw == 0 {
		result.PESQRaw = result.MOSLQO
	}
	return pesqScore{
		RawScore: result.PESQRaw,
		MOSLQO:   result.MOSLQO,
		Method:   "pesq_nb",
	}, nil
}

func writePCMTemp(samples []int16) (string, error) {
	file, err := os.CreateTemp("", "cvs-pesq-*.pcm")
	if err != nil {
		return "", fmt.Errorf("create temp pcm: %w", err)
	}
	defer file.Close()

	payload := make([]byte, len(samples)*2)
	for i, sample := range samples {
		binary.LittleEndian.PutUint16(payload[i*2:], uint16(sample))
	}
	if _, err := file.Write(payload); err != nil {
		return "", fmt.Errorf("write temp pcm: %w", err)
	}
	return file.Name(), nil
}

func discoverPython() (string, error) {
	if configured := os.Getenv(pesqPythonEnv); configured != "" {
		return configured, nil
	}
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		candidate := filepath.Join(venv, "bin", "python")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	for _, candidate := range collectSearchCandidates(".venv/bin/python") {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		return "", fmt.Errorf("discover python: %w", err)
	}
	return pythonPath, nil
}

func discoverPESQScript() (string, error) {
	if configured := os.Getenv(pesqScorerScriptEnv); configured != "" {
		return configured, nil
	}
	for _, rel := range []string{
		"scripts/pesq_nb.py",
		"dist/calltester/scripts/pesq_nb.py",
		"../scripts/pesq_nb.py",
	} {
		for _, candidate := range collectSearchCandidates(rel) {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("discover PESQ scorer script")
}

func collectSearchCandidates(relative string) []string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		for dir := wd; ; dir = filepath.Dir(dir) {
			candidates = append(candidates, filepath.Join(dir, relative))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}
	if exePath, err := os.Executable(); err == nil {
		for dir := filepath.Dir(exePath); ; dir = filepath.Dir(dir) {
			candidates = append(candidates, filepath.Join(dir, relative))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}
	return candidates
}
