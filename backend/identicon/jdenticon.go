package identicon

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

type Point struct {
	X float64
	Y float64
}

type Shape struct {
	Points []Point
	Fill   string
}

type Config struct {
	Size       int
	Padding    float64
	Hues       []float64
	Saturation struct {
		Color     float64
		Grayscale float64
	}
	Lightness struct {
		Color     []float64
		Grayscale []float64
	}
	BackColor string
}

var DefaultConfig = Config{
	Size:    80,
	Padding: 0.08,
	Hues:    nil,
	Saturation: struct {
		Color     float64
		Grayscale float64
	}{
		Color:     0.5,
		Grayscale: 0,
	},
	Lightness: struct {
		Color     []float64
		Grayscale []float64
	}{
		Color:     []float64{0.4, 0.8},
		Grayscale: []float64{0.3, 0.9},
	},
	BackColor: "",
}

func hueToRgb(p, q, t float64) float64 {
	if t < 0 {
		t += 1
	}
	if t > 1 {
		t -= 1
	}
	switch {
	case t < 1.0/6.0:
		return p + (q-p)*6.0*t
	case t < 1.0/2.0:
		return q
	case t < 2.0/3.0:
		return p + (q-p)*(2.0/3.0-t)*6.0
	default:
		return p
	}
}

func hslToRgb(h, s, l float64) (r, g, b float64) {
	if s == 0 {
		return l, l, l
	}

	q := l * (1 + s)
	if l > 0.5 {
		q = l + s - l*s
	}
	p := 2*l - q

	r = hueToRgb(p, q, h+1.0/3.0)
	g = hueToRgb(p, q, h)
	b = hueToRgb(p, q, h-1.0/3.0)

	return
}

func parseHex(str string, pos, length int) int64 {
	// Ensure valid parameters
	if pos < 0 || length <= 0 || pos+length > len(str) {
		return 0
	}
	val, _ := strconv.ParseInt(str[pos:pos+length], 16, 64)
	return val
}

func hashToValue(hash string) float64 {
	if len(hash) < 8 { // Need at least 8 chars for pos 7 + 1 length
		return 0
	}
	return float64(parseHex(hash, min(7, len(hash)-1), 1)) / 15.0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func generateColor(hue, saturation, lightness float64) string {
	r, g, b := hslToRgb(hue, saturation, lightness)
	return fmt.Sprintf("#%02x%02x%02x",
		uint8(r*255),
		uint8(g*255),
		uint8(b*255))
}

func generateShapes(hash string, config Config) []Shape {
	var shapes []Shape
	padding := float64(config.Size) * config.Padding
	cellSize := (float64(config.Size) - 2*padding) / 4

	// Parse hash values for shape generation
	huePos := max(0, len(hash)-7)
	hue := float64(parseHex(hash, huePos, 1)) / 15.0
	sat := config.Saturation.Color
	lightnessRange := config.Lightness.Color

	// Generate colors
	colors := []string{
		generateColor(hue, config.Saturation.Grayscale, lightnessRange[0]),
		generateColor(hue, sat, (lightnessRange[0]+lightnessRange[1])/2),
		generateColor(hue, config.Saturation.Grayscale, lightnessRange[1]),
		generateColor(hue, sat, lightnessRange[1]),
		generateColor(hue, sat, lightnessRange[0]),
	}

	// Generate center shape
	centerShape := parseHex(hash, 1, 1) % 3
	switch centerShape {
	case 0: // Circle
		shapes = append(shapes, Shape{
			Points: []Point{
				{X: padding + 2*cellSize, Y: padding + 2*cellSize},
			},
			Fill: colors[4],
		})
	case 1: // Rectangle
		shapes = append(shapes, Shape{
			Points: []Point{
				{X: padding + 1.5*cellSize, Y: padding + 1.5*cellSize},
				{X: padding + 2.5*cellSize, Y: padding + 1.5*cellSize},
				{X: padding + 2.5*cellSize, Y: padding + 2.5*cellSize},
				{X: padding + 1.5*cellSize, Y: padding + 2.5*cellSize},
			},
			Fill: colors[4],
		})
	case 2: // Path
		shapes = append(shapes, Shape{
			Points: []Point{
				{X: padding + 1.5*cellSize, Y: padding + 2*cellSize},
				{X: padding + 2*cellSize, Y: padding + 1.5*cellSize},
				{X: padding + 2.5*cellSize, Y: padding + 2*cellSize},
				{X: padding + 2*cellSize, Y: padding + 2.5*cellSize},
			},
			Fill: colors[4],
		})
	}

	// Generate surrounding shapes
	for i := 0; i < 4; i++ {
		shapeType := parseHex(hash, 8+i, 1) % 3
		colorIndex := parseHex(hash, 2+i, 1) % 5
		x := float64(i%2)*3 + 1
		y := float64(i/2)*3 + 1

		switch shapeType {
		case 0: // Circle
			shapes = append(shapes, Shape{
				Points: []Point{
					{X: padding + x*cellSize, Y: padding + y*cellSize},
				},
				Fill: colors[colorIndex],
			})
		case 1: // Rectangle
			shapes = append(shapes, Shape{
				Points: []Point{
					{X: padding + (x-0.5)*cellSize, Y: padding + (y-0.5)*cellSize},
					{X: padding + (x+0.5)*cellSize, Y: padding + (y-0.5)*cellSize},
					{X: padding + (x+0.5)*cellSize, Y: padding + (y+0.5)*cellSize},
					{X: padding + (x-0.5)*cellSize, Y: padding + (y+0.5)*cellSize},
				},
				Fill: colors[colorIndex],
			})
		case 2: // Path
			shapes = append(shapes, Shape{
				Points: []Point{
					{X: padding + (x-0.5)*cellSize, Y: padding + y*cellSize},
					{X: padding + x*cellSize, Y: padding + (y-0.5)*cellSize},
					{X: padding + (x+0.5)*cellSize, Y: padding + y*cellSize},
					{X: padding + x*cellSize, Y: padding + (y+0.5)*cellSize},
				},
				Fill: colors[colorIndex],
			})
		}
	}

	return shapes
}

func renderShapesToSVG(shapes []Shape, config Config) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf(
		`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`,
		config.Size, config.Size, config.Size, config.Size))

	if config.BackColor != "" {
		builder.WriteString(fmt.Sprintf(
			`<rect width="100%%" height="100%%" fill="%s"/>`, config.BackColor))
	}

	for _, shape := range shapes {
		builder.WriteString(fmt.Sprintf(
			`<path fill="%s" d="%s"/>`, shape.Fill, pointsToPath(shape.Points)))
	}

	builder.WriteString("</svg>")
	return builder.String()
}

func pointsToPath(points []Point) string {
	var path strings.Builder
	for i, p := range points {
		if i == 0 {
			path.WriteString(fmt.Sprintf("M%.2f %.2f", p.X, p.Y))
		} else {
			path.WriteString(fmt.Sprintf("L%.2f %.2f", p.X, p.Y))
		}
	}
	path.WriteString("Z")
	return path.String()
}

func GenerateIcon(input string, config Config) string {
	// First hash the input to ensure consistent format
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Normalize hash length
	normalized := normalizeHash(hash)

	// Generate shapes based on hash
	shapes := generateShapes(normalized, config)

	// Render to SVG
	return renderShapesToSVG(shapes, config)
}

func normalizeHash(hash string) string {
	if len(hash) >= 11 {
		return hash
	}
	// Fallback to SHA1 if hash is too short
	h := sha1.New()
	h.Write([]byte(hash))
	return hex.EncodeToString(h.Sum(nil))
}
