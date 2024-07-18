package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/fatih/camelcase"
	"github.com/pmoroney/rivian-prometheus/rivian"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed login.html
//go:embed otp.html
var indexTemplateFS embed.FS

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
	p.collectors["need_login"] = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "rivian",
			Subsystem: "account",
			Name:      "need_login",
		},
		[]string{},
	)
	prometheus.MustRegister(p.collectors["need_login"])

	p.collectors["last_update"] = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "rivian",
			Subsystem: "vehicle_info",
			Name:      "last_update",
		},
		[]string{
			"vehicle_name",
		},
	)
	prometheus.MustRegister(p.collectors["last_update"])

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
	p.collectors["last_update"].With(prometheus.Labels{"vehicle_name": vehicle_name}).SetToCurrentTime()
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

type loginFlow struct {
	c *rivian.Client
	p *Metrics

	mu       sync.Mutex
	loggedIn bool
	needOTP  bool
	email    string // Temporary storage for second OTP login command
	vehicles []rivian.Vehicle
}

func newLoginFlow(c *rivian.Client, p *Metrics) *loginFlow {
	return &loginFlow{
		c: c,
		p: p,
	}
}

func (l *loginFlow) IsLoggedIn() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loggedIn
}

func (l *loginFlow) Vehicles() []rivian.Vehicle {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.vehicles
}

func (l *loginFlow) Logout() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.logoutWithLock()
}

func (l *loginFlow) logoutWithLock() {
	l.p.collectors["need_login"].With(prometheus.Labels{}).Set(1.0)
	l.loggedIn = false
	l.needOTP = false
	l.email = ""
	l.vehicles = []rivian.Vehicle{}
}

func (l *loginFlow) Login(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.loginWithLock(ctx)
}

func (l *loginFlow) loginWithLock(ctx context.Context) error {
	l.p.collectors["need_login"].With(prometheus.Labels{}).Set(0.0)
	l.loggedIn = true
	l.needOTP = false
	l.email = ""

	var err error
	l.vehicles, err = l.c.GetVehicles(ctx)
	return err
}

func (l *loginFlow) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/login":
		l.handleLogin(w, req)
	case "/otp":
		l.handleOTP(w, req)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (l *loginFlow) handleLogin(w http.ResponseWriter, req *http.Request) {
	tmpl := template.Must(template.ParseFS(indexTemplateFS, "login.html"))

	formData := struct{ Error string }{}

	if req.Method == http.MethodGet {
		tmpl.Execute(w, formData)
		return
	}

	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	email := req.FormValue("email")
	password := req.FormValue("password")

	if email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		formData.Error = "Both email and password fields must be non-empty"
		tmpl.Execute(w, formData)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loggedIn {
		formData.Error = "Already logged in"
		tmpl.Execute(w, formData)
		return
	}

	otp, err := l.c.Login(req.Context(), email, password)

	if err != nil {
		log.Print(err)
		formData.Error = "Error logging in: " + err.Error()
		tmpl.Execute(w, formData)
		return
	}

	if otp {
		l.needOTP = true
		l.email = email
		otpTemplate := template.Must(template.ParseFS(indexTemplateFS, "otp.html"))
		otpTemplate.Execute(w, formData)
		return
	}

	err = l.loginWithLock(req.Context())

	if err != nil {
		log.Print(err)
		formData.Error = "Error getting vehicles: " + err.Error()
		tmpl.Execute(w, formData)
		return
	}

	w.Write([]byte("Success"))
}

func (l *loginFlow) handleOTP(w http.ResponseWriter, req *http.Request) {
	tmpl := template.Must(template.ParseFS(indexTemplateFS, "otp.html"))

	formData := struct{ Error string }{}

	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	otp := req.FormValue("otp")

	if otp == "" {
		formData.Error = "OTP token required"
		tmpl.Execute(w, formData)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.needOTP {
		formData.Error = "OTP not required"
		tmpl.Execute(w, formData)
		return
	}

	err := l.c.ValidateOTP(req.Context(), l.email, otp)

	if err != nil {
		log.Print(err)
		formData.Error = "Error validating token: " + err.Error()
		tmpl.Execute(w, formData)
		return
	}

	err = l.loginWithLock(req.Context())

	if err != nil {
		log.Print(err)
		formData.Error = "Error getting vehicles: " + err.Error()
		tmpl.Execute(w, formData)
		return
	}

	w.Write([]byte("Success"))
}

func main() {
	p := NewPrometheus()
	p.CreateMetrics()
	var debug bool
	var sessionFile string
	flag.BoolVar(&debug, "d", false, "debug")
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

	loginHandler := newLoginFlow(c, p)

	if c.NeedsLogin() {
		loginHandler.Logout()
	} else {
		loginHandler.Login(context.Background())
	}

	done := make(chan struct{})
	ticker := time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				for _, v := range loginHandler.Vehicles() {
					state, err := c.GetVehicleState(ctx, v)
					if err != nil {
						log.Println(err)
						if strings.Contains(err.Error(), "UNAUTHENTICATED") {
							loginHandler.Logout()
						}
						continue
					}
					if state.OtaCurrentVersionWeek.Value == 0 {
						// Rivian once returned all nulls
						log.Println("Skipping nil values")
						continue
					}
					p.CollectMetrics(v.Name, state)
				}
				if loginHandler.IsLoggedIn() {
					c.WriteSessionData(sessionFile)
				}
			}
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/", loginHandler)
	err = http.ListenAndServe(":9666", nil)
	done <- struct{}{}
	ticker.Stop()
	log.Fatal(err)
}
