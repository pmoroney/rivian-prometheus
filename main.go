package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/fatih/camelcase"
	"github.com/pmoroney/rivian-prometheus/rivian"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	collectors map[string]*prometheus.GaugeVec
}

func NewPrometheus() *Metrics {
	return &Metrics{
		collectors: make(map[string]*prometheus.GaugeVec),
	}
}

func toSnakeCase(s string) string {
	parts := camelcase.Split(s)
	for i := 0; i < len(parts); i++ {
		parts[i] = strings.ToLower(parts[i])
	}
	return strings.Join(parts, "_")
}

func (p *Metrics) CreateMetrics() {
	var s rivian.VehicleState
	state := reflect.ValueOf(s)
	for i := 0; i < state.NumField(); i++ {
		field := state.Type().Field(i)
		name := toSnakeCase(field.Name)
		switch field.Type.Name() {
		case "FloatValue":
			p.collectors[name] = prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "rivian",
					Subsystem: "vehicle_info",
					Name:      name,
				},
				[]string{
					"vehicle_name",
				},
			)
			prometheus.MustRegister(p.collectors[name])
		case "StringValue":
			p.collectors[name] = prometheus.NewGaugeVec(
				prometheus.GaugeOpts{
					Namespace: "rivian",
					Subsystem: "vehicle_info",
					Name:      name,
				},
				[]string{
					"vehicle_name",
					"value",
				},
			)
			prometheus.MustRegister(p.collectors[name])
		case "LocationValue":
			for _, f := range []string{"latitude", "longitude"} {
				name := name + "_" + f
				p.collectors[name] = prometheus.NewGaugeVec(
					prometheus.GaugeOpts{
						Namespace: "rivian",
						Subsystem: "vehicle_info",
						Name:      name,
					},
					[]string{
						"vehicle_name",
					},
				)
				prometheus.MustRegister(p.collectors[name])
			}
		case "LocationErrorValue":
			for _, f := range []string{"position_vertical", "position_horizontal", "speed", "bearing"} {
				name := name + "_" + f
				p.collectors[name] = prometheus.NewGaugeVec(
					prometheus.GaugeOpts{
						Namespace: "rivian",
						Subsystem: "vehicle_info",
						Name:      name,
					},
					[]string{
						"vehicle_name",
					},
				)
				prometheus.MustRegister(p.collectors[name])
			}
		default:
			fmt.Printf("unknown type: %s: %s\n", field.Type.Name(), name)
		}
	}

}
func (p *Metrics) CollectMetrics(vehicle_name string, v *rivian.VehicleState) {
	state := reflect.ValueOf(v).Elem()
	for i := 0; i < state.NumField(); i++ {
		field := state.Type().Field(i)
		name := toSnakeCase(field.Name)
		switch field.Type.Name() {
		case "FloatValue":
			p.collectors[name].With(prometheus.Labels{"vehicle_name": vehicle_name}).Set(state.FieldByName(field.Name).FieldByName("Value").Float())
		case "StringValue":
			p.collectors[name].Reset()
			p.collectors[name].With(prometheus.Labels{"vehicle_name": vehicle_name, "value": state.FieldByName(field.Name).FieldByName("Value").String()}).Set(1)
		case "LocationValue":
			for _, fname := range []string{"Latitude", "Longitude"} {
				f := toSnakeCase(fname)
				p.collectors[name+"_"+f].With(prometheus.Labels{"vehicle_name": vehicle_name}).Set(state.FieldByName(field.Name).FieldByName(fname).Float())
			}
		case "LocationErrorValue":
			for _, fname := range []string{"PositionVertical", "PositionHorizontal", "Speed", "Bearing"} {
				f := toSnakeCase(fname)
				p.collectors[name+"_"+f].With(prometheus.Labels{"vehicle_name": vehicle_name}).Set(state.FieldByName(field.Name).FieldByName(fname).Float())
			}
		default:
			fmt.Printf("unknown type: %s: %s\n", field.Type.Name(), name)
		}
	}

}

func main() {
	p := NewPrometheus()
	p.CreateMetrics()
	var login, debug bool
	var sessionFile string
	flag.BoolVar(&debug, "d", false, "debug")
	flag.BoolVar(&login, "l", false, "login and save session")
	flag.StringVar(&sessionFile, "s", ".rivian_session", "filename for session storage")
	ctx := context.Background()
	c := rivian.NewClient()
	c.Debug(debug)
	c.ReadSessionData(sessionFile)
	defer c.WriteSessionData(sessionFile)

	err := c.GetCSRFToken(ctx)
	if err != nil {
		log.Fatal(err)
	}

	if login || c.NeedsLogin() {
		stdin := bufio.NewReader(os.Stdin)
		fmt.Println("Please enter your email:")
		email, _ := stdin.ReadString('\n')
		email = strings.Replace(email, "\n", "", -1)
		fmt.Println("Please enter your password:")
		password, _ := stdin.ReadString('\n')
		password = strings.Replace(password, "\n", "", -1)
		otp, err := c.Login(ctx, email, password)
		if err != nil {
			log.Fatal(err)
		}
		if otp {
			fmt.Println("Please enter your token:")
			text, _ := stdin.ReadString('\n')
			text = strings.Replace(text, "\n", "", -1)
			err = c.ValidateOTP(ctx, email, text)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	vehicles, err := c.GetVehicles(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range vehicles {
		state, err := c.GetVehicleState(ctx, v)
		if err != nil {
			log.Fatal(err)
		}
		p.CollectMetrics(v.Name, state)
	}

	done := make(chan struct{})
	ticker := time.NewTicker(30 * time.Second)

	go func(vehicles []rivian.Vehicle) {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				for _, v := range vehicles {
					state, err := c.GetVehicleState(ctx, v)
					if err != nil {
						log.Println(err)
						return
					}
					if state.OtaCurrentVersionWeek.Value == 0 {
						// Rivian once returned all nulls
						log.Println("Skipping nil values")
						continue
					}
					p.CollectMetrics(v.Name, state)
				}
			}
		}
	}(vehicles)

	http.Handle("/metrics", promhttp.Handler())
	err = http.ListenAndServe(":9666", nil)
	done <- struct{}{}
	ticker.Stop()
	log.Fatal(err)
}
