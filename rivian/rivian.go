package rivian

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/hasura/go-graphql-client"
)

type SessionTokens struct {
	CSRF    string
	App     string
	User    string
	Access  string
	Refresh string
	OTP     string
}

type Client struct {
	client     *graphql.Client
	tokens     SessionTokens
	httpClient *http.Client
}

func NewClient() *Client {
	c := &Client{}
	c.httpClient = &http.Client{
		Transport: &loggingTransport{},
	}
	c.client = graphql.NewClient("https://rivian.com/api/gql/gateway/graphql", c.httpClient).WithRequestModifier(c.AddHeaders)
	return c
}

func (c *Client) NeedsLogin() bool {
	return c.tokens.User == ""
}

func (c *Client) Debug(on bool) {
	c.client = c.client.WithDebug(on)
	c.httpClient.Transport.(*loggingTransport).Log = true
}

func (c *Client) AddHeaders(req *http.Request) {
	if c.tokens.App != "" {
		req.Header.Set("a-sess", c.tokens.App)
	}
	if c.tokens.User != "" {
		req.Header.Set("u-sess", c.tokens.User)
	}
	if c.tokens.CSRF != "" {
		req.Header.Set("csrf-token", c.tokens.CSRF)
	}
	req.Header.Set("Apollographql-Client-Name", "com.rivian.ios.consumer-apollo-ios")
	req.Header.Set("User-Agent", "RivianApp/707 CFNetwork/1237 Darwin/20.4.0")
	req.Header.Set("Dc-Cid", "m-ios-"+uuid.New().String())
}

func (c *Client) GetCSRFToken(ctx context.Context) error {
	type CreateCSRFToken struct {
		CreateCsrfToken struct {
			CsrfToken       string
			AppSessionToken string
		} `json:"createCsrfToken"`
	}

	var resp CreateCSRFToken
	err := c.client.Mutate(ctx, &resp, map[string]interface{}{}, graphql.OperationName("CreateCSRFToken"))
	if err != nil {
		log.Printf("error: %#v", err)
		return err
	}

	c.tokens.CSRF = resp.CreateCsrfToken.CsrfToken
	c.tokens.App = resp.CreateCsrfToken.AppSessionToken
	return nil
}

func (c *Client) Login(ctx context.Context, email string, password string) (bool, error) {
	type Login struct {
		Login struct {
			MobileLoginResponse struct {
				AccessToken      string `json:"accessToken"`
				RefreshToken     string `json:"refreshToken"`
				UserSessionToken string `json:"userSessionToken"`
			} `graphql:"... on MobileLoginResponse"`
			MobileMFALoginResponse struct {
				OTPToken string `json:"otpToken"`
			} `graphql:"... on MobileMFALoginResponse"`
		} `graphql:"login(email: $email, password: $password)"`
	}

	var resp Login
	variables := map[string]interface{}{
		"email":    email,
		"password": password,
	}
	err := c.client.Mutate(ctx, &resp, variables, graphql.OperationName("Login"))
	if err != nil {
		log.Printf("error: %#v", err)
		return false, err
	}

	// if no MFA enabled
	if resp.Login.MobileLoginResponse.UserSessionToken != "" {
		c.tokens.User = resp.Login.MobileLoginResponse.UserSessionToken
		c.tokens.Access = resp.Login.MobileLoginResponse.AccessToken
		c.tokens.Refresh = resp.Login.MobileLoginResponse.RefreshToken
		return false, nil
	}

	c.tokens.OTP = resp.Login.MobileMFALoginResponse.OTPToken
	return true, nil
}

func (c *Client) ValidateOTP(ctx context.Context, email string, otp string) error {
	type LoginWithOTP struct {
		LoginWithOTP struct {
			AccessToken      string `json:"accessToken"`
			RefreshToken     string `json:"refreshToken"`
			UserSessionToken string `json:"userSessionToken"`
		} `graphql:"loginWithOTP(email: $email, otpCode: $otpCode, otpToken: $otpToken)"`
	}

	var resp LoginWithOTP
	variables := map[string]interface{}{
		"email":    email,
		"otpCode":  otp,
		"otpToken": c.tokens.OTP,
	}
	err := c.client.Mutate(ctx, &resp, variables, graphql.OperationName("LoginWithOTP"))
	if err != nil {
		log.Printf("error: %#v", err)
		return err
	}

	c.tokens.User = resp.LoginWithOTP.UserSessionToken
	c.tokens.Access = resp.LoginWithOTP.AccessToken
	c.tokens.Refresh = resp.LoginWithOTP.RefreshToken
	return nil

}

type Vehicle struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) GetVehicles(ctx context.Context) ([]Vehicle, error) {
	type GetUserInfo struct {
		CurrentUser struct {
			ID       string    `json:"id"`
			Vehicles []Vehicle `json:"vehicles"`
		} `graphql:"currentUser"`
	}

	var resp GetUserInfo
	variables := map[string]interface{}{}
	err := c.client.Query(ctx, &resp, variables, graphql.OperationName("getUserInfo"))
	if err != nil {
		log.Printf("error: %#v", err)
		return nil, err
	}

	return resp.CurrentUser.Vehicles, nil

}

type FloatValue struct {
	Value     float64   `json:"value,omitempty"`
	Timestamp time.Time `json:"timeStamp,omitempty" graphql:"timeStamp"`
}

type StringValue struct {
	Value     string    `json:"value,omitempty"`
	Timestamp time.Time `json:"timeStamp,omitempty" graphql:"timeStamp"`
}

type LocationValue struct {
	Latitude  float64   `json:"latitude,omitempty"`
	Longitude float64   `json:"longitude,omitempty"`
	Timestamp time.Time `json:"timeStamp,omitempty" graphql:"timeStamp"`
}

type LocationErrorValue struct {
	PositionVertical   float64   `json:"positionVertical,omitempty"`
	PositionHorizontal float64   `json:"positionHorizontal,omitempty"`
	Speed              float64   `json:"speed,omitempty"`
	Bearing            float64   `json:"bearing,omitempty"`
	Timestamp          time.Time `json:"timeStamp,omitempty" graphql:"timeStamp"`
}

type VehicleState struct {
	GNSSLocation                      LocationValue      `json:"gnssLocation,omitempty"`
	GNSSError                         LocationErrorValue `json:"gnssError,omitempty"`
	AlarmSoundStatus                  StringValue        `json:"alarmSoundStatus,omitempty"`
	BatteryCapacity                   FloatValue         `json:"batteryCapacity,omitempty"`
	BatteryHvThermalEvent             StringValue        `json:"batteryHvThermalEvent,omitempty"`
	BatteryHvThermalEventPropagation  StringValue        `json:"batteryHvThermalEventPropagation,omitempty"`
	BatteryLevel                      FloatValue         `json:"batteryLevel,omitempty"`
	BatteryLimit                      FloatValue         `json:"batteryLimit,omitempty"`
	BrakeFluidLow                     StringValue        `json:"brakeFluidLow,omitempty"`
	BtmFfHardwareFailureStatus        StringValue        `json:"btmFfHardwareFailureStatus,omitempty"`
	BtmIcHardwareFailureStatus        StringValue        `json:"btmIcHardwareFailureStatus,omitempty"`
	BtmLfdHardwareFailureStatus       StringValue        `json:"btmLfdHardwareFailureStatus,omitempty"`
	BtmRfHardwareFailureStatus        StringValue        `json:"btmRfHardwareFailureStatus,omitempty"`
	BtmRfdHardwareFailureStatus       StringValue        `json:"btmRfdHardwareFailureStatus,omitempty"`
	CabinClimateDriverTemperature     FloatValue         `json:"cabinClimateDriverTemperature,omitempty"`
	CabinClimateInteriorTemperature   FloatValue         `json:"cabinClimateInteriorTemperature,omitempty"`
	CabinPreconditioningStatus        StringValue        `json:"cabinPreconditioningStatus,omitempty"`
	CabinPreconditioningType          StringValue        `json:"cabinPreconditioningType,omitempty"`
	CarWashMode                       StringValue        `json:"carWashMode,omitempty"`
	ChargePortState                   StringValue        `json:"chargePortState,omitempty"`
	ChargerDerateStatus               StringValue        `json:"chargerDerateStatus,omitempty"`
	ChargerState                      StringValue        `json:"chargerState,omitempty"`
	ChargerStatus                     StringValue        `json:"chargerStatus,omitempty"`
	ClosureFrunkClosed                StringValue        `json:"closureFrunkClosed,omitempty"`
	ClosureFrunkLocked                StringValue        `json:"closureFrunkLocked,omitempty"`
	ClosureFrunkNextAction            StringValue        `json:"closureFrunkNextAction,omitempty"`
	ClosureLiftgateClosed             StringValue        `json:"closureLiftgateClosed,omitempty"`
	ClosureLiftgateLocked             StringValue        `json:"closureLiftgateLocked,omitempty"`
	ClosureLiftgateNextAction         StringValue        `json:"closureLiftgateNextAction,omitempty"`
	ClosureSideBinLeftClosed          StringValue        `json:"closureSideBinLeftClosed,omitempty"`
	ClosureSideBinLeftLocked          StringValue        `json:"closureSideBinLeftLocked,omitempty"`
	ClosureSideBinLeftNextAction      StringValue        `json:"closureSideBinLeftNextAction,omitempty"`
	ClosureSideBinRightClosed         StringValue        `json:"closureSideBinRightClosed,omitempty"`
	ClosureSideBinRightLocked         StringValue        `json:"closureSideBinRightLocked,omitempty"`
	ClosureSideBinRightNextAction     StringValue        `json:"closureSideBinRightNextAction,omitempty"`
	ClosureTailgateClosed             StringValue        `json:"closureTailgateClosed,omitempty"`
	ClosureTailgateLocked             StringValue        `json:"closureTailgateLocked,omitempty"`
	ClosureTailgateNextAction         StringValue        `json:"closureTailgateNextAction,omitempty"`
	ClosureTonneauClosed              StringValue        `json:"closureTonneauClosed,omitempty"`
	ClosureTonneauLocked              StringValue        `json:"closureTonneauLocked,omitempty"`
	ClosureTonneauNextAction          StringValue        `json:"closureTonneauNextAction,omitempty"`
	DefrostDefogStatus                StringValue        `json:"defrostDefogStatus,omitempty"`
	DistanceToEmpty                   FloatValue         `json:"distanceToEmpty,omitempty"`
	DoorFrontLeftClosed               StringValue        `json:"doorFrontLeftClosed,omitempty"`
	DoorFrontLeftLocked               StringValue        `json:"doorFrontLeftLocked,omitempty"`
	DoorFrontRightClosed              StringValue        `json:"doorFrontRightClosed,omitempty"`
	DoorFrontRightLocked              StringValue        `json:"doorFrontRightLocked,omitempty"`
	DoorRearLeftClosed                StringValue        `json:"doorRearLeftClosed,omitempty"`
	DoorRearLeftLocked                StringValue        `json:"doorRearLeftLocked,omitempty"`
	DoorRearRightClosed               StringValue        `json:"doorRearRightClosed,omitempty"`
	DoorRearRightLocked               StringValue        `json:"doorRearRightLocked,omitempty"`
	DriveMode                         StringValue        `json:"driveMode,omitempty"`
	GearGuardLocked                   StringValue        `json:"gearGuardLocked,omitempty"`
	GearGuardVideoMode                StringValue        `json:"gearGuardVideoMode,omitempty"`
	GearGuardVideoStatus              StringValue        `json:"gearGuardVideoStatus,omitempty"`
	GearGuardVideoTermsAccepted       StringValue        `json:"gearGuardVideoTermsAccepted,omitempty"`
	GearStatus                        StringValue        `json:"gearStatus,omitempty"`
	GnssAltitude                      FloatValue         `json:"gnssAltitude,omitempty"`
	GnssBearing                       FloatValue         `json:"gnssBearing,omitempty"`
	GnssSpeed                         FloatValue         `json:"gnssSpeed,omitempty"`
	LimitedAccelCold                  FloatValue         `json:"limitedAccelCold,omitempty"`
	LimitedRegenCold                  FloatValue         `json:"limitedRegenCold,omitempty"`
	OtaAvailableVersion               StringValue        `json:"otaAvailableVersion,omitempty"`
	OtaAvailableVersionGitHash        StringValue        `json:"otaAvailableVersionGitHash,omitempty"`
	OtaAvailableVersionNumber         FloatValue         `json:"otaAvailableVersionNumber,omitempty"`
	OtaAvailableVersionWeek           FloatValue         `json:"otaAvailableVersionWeek,omitempty"`
	OtaAvailableVersionYear           FloatValue         `json:"otaAvailableVersionYear,omitempty"`
	OtaCurrentStatus                  StringValue        `json:"otaCurrentStatus,omitempty"`
	OtaCurrentVersion                 StringValue        `json:"otaCurrentVersion,omitempty"`
	OtaCurrentVersionGitHash          StringValue        `json:"otaCurrentVersionGitHash,omitempty"`
	OtaCurrentVersionNumber           FloatValue         `json:"otaCurrentVersionNumber,omitempty"`
	OtaCurrentVersionWeek             FloatValue         `json:"otaCurrentVersionWeek,omitempty"`
	OtaCurrentVersionYear             FloatValue         `json:"otaCurrentVersionYear,omitempty"`
	OtaDownloadProgress               FloatValue         `json:"otaDownloadProgress,omitempty"`
	OtaInstallDuration                FloatValue         `json:"otaInstallDuration,omitempty"`
	OtaInstallProgress                FloatValue         `json:"otaInstallProgress,omitempty"`
	OtaInstallReady                   StringValue        `json:"otaInstallReady,omitempty"`
	OtaInstallTime                    FloatValue         `json:"otaInstallTime,omitempty"`
	OtaInstallType                    StringValue        `json:"otaInstallType,omitempty"`
	OtaStatus                         StringValue        `json:"otaStatus,omitempty"`
	PetModeStatus                     StringValue        `json:"petModeStatus,omitempty"`
	PetModeTemperatureStatus          StringValue        `json:"petModeTemperatureStatus,omitempty"`
	PowerState                        StringValue        `json:"powerState,omitempty"`
	RangeThreshold                    StringValue        `json:"rangeThreshold,omitempty"`
	RearHitchStatus                   StringValue        `json:"rearHitchStatus,omitempty"`
	RemoteChargingAvailable           FloatValue         `json:"remoteChargingAvailable,omitempty"`
	SeatFrontLeftHeat                 StringValue        `json:"seatFrontLeftHeat,omitempty"`
	SeatFrontLeftVent                 StringValue        `json:"seatFrontLeftVent,omitempty"`
	SeatFrontRightHeat                StringValue        `json:"seatFrontRightHeat,omitempty"`
	SeatFrontRightVent                StringValue        `json:"seatFrontRightVent,omitempty"`
	SeatRearLeftHeat                  StringValue        `json:"seatRearLeftHeat,omitempty"`
	SeatRearRightHeat                 StringValue        `json:"seatRearRightHeat,omitempty"`
	SeatThirdRowLeftHeat              StringValue        `json:"seatThirdRowLeftHeat,omitempty"`
	SeatThirdRowRightHeat             StringValue        `json:"seatThirdRowRightHeat,omitempty"`
	ServiceMode                       StringValue        `json:"serviceMode,omitempty"`
	SteeringWheelHeat                 StringValue        `json:"steeringWheelHeat,omitempty"`
	TimeToEndOfCharge                 FloatValue         `json:"timeToEndOfCharge,omitempty"`
	TirePressureStatusFrontLeft       StringValue        `json:"tirePressureStatusFrontLeft,omitempty"`
	TirePressureStatusFrontRight      StringValue        `json:"tirePressureStatusFrontRight,omitempty"`
	TirePressureStatusRearLeft        StringValue        `json:"tirePressureStatusRearLeft,omitempty"`
	TirePressureStatusRearRight       StringValue        `json:"tirePressureStatusRearRight,omitempty"`
	TirePressureStatusValidFrontLeft  StringValue        `json:"tirePressureStatusValidFrontLeft,omitempty"`
	TirePressureStatusValidFrontRight StringValue        `json:"tirePressureStatusValidFrontRight,omitempty"`
	TirePressureStatusValidRearLeft   StringValue        `json:"tirePressureStatusValidRearLeft,omitempty"`
	TirePressureStatusValidRearRight  StringValue        `json:"tirePressureStatusValidRearRight,omitempty"`
	TrailerStatus                     StringValue        `json:"trailerStatus,omitempty"`
	TwelveVoltBatteryHealth           StringValue        `json:"twelveVoltBatteryHealth,omitempty"`
	VehicleMileage                    FloatValue         `json:"vehicleMileage,omitempty"`
	WindowFrontLeftCalibrated         StringValue        `json:"windowFrontLeftCalibrated,omitempty"`
	WindowFrontLeftClosed             StringValue        `json:"windowFrontLeftClosed,omitempty"`
	WindowFrontRightCalibrated        StringValue        `json:"windowFrontRightCalibrated,omitempty"`
	WindowFrontRightClosed            StringValue        `json:"windowFrontRightClosed,omitempty"`
	WindowRearLeftCalibrated          StringValue        `json:"windowRearLeftCalibrated,omitempty"`
	WindowRearLeftClosed              StringValue        `json:"windowRearLeftClosed,omitempty"`
	WindowRearRightCalibrated         StringValue        `json:"windowRearRightCalibrated,omitempty"`
	WindowRearRightClosed             StringValue        `json:"windowRearRightClosed,omitempty"`
	WindowsNextAction                 StringValue        `json:"windowsNextAction,omitempty"`
	WiperFluidState                   StringValue        `json:"wiperFluidState,omitempty"`
}

func (c *Client) GetVehicleState(ctx context.Context, v Vehicle) (*VehicleState, error) {
	type GetVehicleState struct {
		VehicleState VehicleState `json:"vehicleState" graphql:"vehicleState(id: $vehicleID)"`
	}

	var resp GetVehicleState
	variables := map[string]interface{}{
		"vehicleID": v.ID,
	}
	err := c.client.Query(ctx, &resp, variables, graphql.OperationName("GetVehicleState"))
	if err != nil {
		log.Printf("error: %#v", err)
		return nil, err
	}

	return &resp.VehicleState, nil

}

func (c *Client) WriteSessionData(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	return encoder.Encode(c.tokens)
}

func (c *Client) ReadSessionData(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	return decoder.Decode(&c.tokens)
}

type loggingTransport struct {
	Log bool
}

func (s *loggingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var bytes []byte
	if s.Log && r != nil {
		bytes, _ = httputil.DumpRequestOut(r, true)
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	// err is returned after dumping the response

	if s.Log && resp != nil {
		respBytes, _ := httputil.DumpResponse(resp, true)
		bytes = append(bytes, respBytes...)

		fmt.Printf("%s\n", bytes)
	}

	return resp, err
}
