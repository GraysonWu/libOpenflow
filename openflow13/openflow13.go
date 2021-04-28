package openflow13

// Package openflow13 provides OpenFlow 1.3 structs along with Read
// and Write methods for each.
// OpenFlow Wire Protocol 0x04
//
// Struct documentation is taken from the OpenFlow Switch
// Specification Version 1.3.3.
// https://www.opennetworking.org/images/stories/downloads/sdn-resources/onf-specifications/openflow/openflow-spec-v1.3.3.pdf

import (
	"encoding/binary"
	"errors"
	log "github.com/sirupsen/logrus"
	"net"

	"antrea-io/libOpenflow/common"
	"antrea-io/libOpenflow/protocol"
	"antrea-io/libOpenflow/util"
)

const (
	VERSION = 4
)

// Returns a new OpenFlow header with version field set to v1.3.
var NewOfp13Header func() common.Header = common.NewHeaderGenerator(VERSION)

// Echo request/reply messages can be sent from either the
// switch or the controller, and must return an echo reply. They
// can be used to indicate the latency, bandwidth, and/or
// liveness of a controller-switch connection.
func NewEchoRequest() *common.Header {
	h := NewOfp13Header()
	h.Type = Type_EchoRequest
	return &h
}

// Echo request/reply messages can be sent from either the
// switch or the controller, and must return an echo reply. They
// can be used to indicate the latency, bandwidth, and/or
// liveness of a controller-switch connection.
func NewEchoReply() *common.Header {
	h := NewOfp13Header()
	h.Type = Type_EchoReply
	return &h
}

// ofp_type 1.3
const (
	/* Immutable messages. */
	Type_Hello        = 0
	Type_Error        = 1
	Type_EchoRequest  = 2
	Type_EchoReply    = 3
	Type_Experimenter = 4

	/* Switch configuration messages. */
	Type_FeaturesRequest  = 5
	Type_FeaturesReply    = 6
	Type_GetConfigRequest = 7
	Type_GetConfigReply   = 8
	Type_SetConfig        = 9

	/* Asynchronous messages. */
	Type_PacketIn    = 10
	Type_FlowRemoved = 11
	Type_PortStatus  = 12

	/* Controller command messages. */
	Type_PacketOut = 13
	Type_FlowMod   = 14
	Type_GroupMod  = 15
	Type_PortMod   = 16
	Type_TableMod  = 17

	/* Multipart messages. */
	Type_MultiPartRequest = 18
	Type_MultiPartReply   = 19

	/* Barrier messages. */
	Type_BarrierRequest = 20
	Type_BarrierReply   = 21

	/* Queue Configuration messages. */
	Type_QueueGetConfigRequest = 22
	Type_QueueGetConfigReply   = 23

	/* Controller role change request messages. */
	Type_RoleRequest = 24
	Type_RoleReply   = 25

	/* Asynchronous message configuration. */
	Type_GetAsyncRequest = 26
	Type_GetAsyncReply   = 27
	Type_SetAsync        = 28

	/* Meters and rate limiters configuration messages. */
	Type_MeterMod = 29
	Type_PacketIn2 = 30
)

func Parse(b []byte) (message util.Message, err error) {
	log.Infof("=============WTF type you are? %d", b[1])
	switch b[1] {
	case Type_Hello:
		message = new(common.Hello)
		err = message.UnmarshalBinary(b)
	case Type_Error:
		errMsg := new(ErrorMsg)
		err = errMsg.UnmarshalBinary(b)
		if err != nil {
			return
		}
		switch errMsg.Type {
		case ET_EXPERIMENTER:
			message = new(VendorError)
			err = message.UnmarshalBinary(b)
		default:
			message = errMsg
		}
	case Type_EchoRequest:
		message = new(common.Header)
		err = message.UnmarshalBinary(b)
	case Type_EchoReply:
		message = new(common.Header)
		err = message.UnmarshalBinary(b)
	case Type_Experimenter:
		message = new(VendorHeader)
		err = message.UnmarshalBinary(b)
	case Type_FeaturesRequest:
		message = NewFeaturesRequest()
		err = message.UnmarshalBinary(b)
	case Type_FeaturesReply:
		message = NewFeaturesReply()
		err = message.UnmarshalBinary(b)
	case Type_GetConfigRequest:
		message = new(common.Header)
		err = message.UnmarshalBinary(b)
	case Type_GetConfigReply:
		message = new(SwitchConfig)
		err = message.UnmarshalBinary(b)
	case Type_SetConfig:
		message = NewSetConfig()
		err = message.UnmarshalBinary(b)
	case Type_PacketIn:
		log.Infof("WOC packetin")
		log.Infof("duo JB chang ne %d", len(b))
		log.Infof("kankan byte: %s", b)
		message = new(PacketIn)
		err = message.UnmarshalBinary(b)
	case Type_FlowRemoved:
		message = NewFlowRemoved()
		err = message.UnmarshalBinary(b)
	case Type_PortStatus:
		message = new(PortStatus)
		err = message.UnmarshalBinary(b)
	case Type_PacketOut:
		break
	case Type_FlowMod:
		message = NewFlowMod()
		err = message.UnmarshalBinary(b)
	case Type_GroupMod:
		break
	case Type_PortMod:
		break
	case Type_TableMod:
		break
	case Type_BarrierRequest:
		message = new(common.Header)
		err = message.UnmarshalBinary(b)
	case Type_BarrierReply:
		message = new(common.Header)
		err = message.UnmarshalBinary(b)
	case Type_QueueGetConfigRequest:
		break
	case Type_QueueGetConfigReply:
		break
	case Type_MultiPartRequest:
		message = new(MultipartRequest)
		err = message.UnmarshalBinary(b)
	case Type_MultiPartReply:
		message = new(MultipartReply)
		err = message.UnmarshalBinary(b)
	case Type_PacketIn2:
		log.Infof("WOC packetin2")
		message = new(PacketIn2)
		err = message.UnmarshalBinary(b)
	default:
		err = errors.New("An unknown v1.0 packet type was received. Parse function will discard data.")
	}
	return
}

// When the controller wishes to send a packet out through the
// datapath, it uses the OFPT_PACKET_OUT message: The buffer_id
// is the same given in the ofp_packet_in message. If the
// buffer_id is -1, then the packet data is included in the data
// array. If OFPP_TABLE is specified as the output port of an
// action, the in_port in the packet_out message is used in the
// flow table lookup.
type PacketOut struct {
	common.Header
	BufferId   uint32
	InPort     uint32
	ActionsLen uint16
	pad        []byte
	Actions    []Action
	Data       util.Message
}

func NewPacketOut() *PacketOut {
	p := new(PacketOut)
	p.Header = NewOfp13Header()
	p.Header.Type = Type_PacketOut
	p.BufferId = 0xffffffff
	p.InPort = P_ANY
	p.ActionsLen = 0
	p.pad = make([]byte, 6)
	p.Actions = make([]Action, 0)
	return p
}

func (p *PacketOut) AddAction(act Action) {
	p.Actions = append(p.Actions, act)
	p.ActionsLen += act.Len()
}

func (p *PacketOut) Len() (n uint16) {
	n += p.Header.Len()
	n += 16
	for _, a := range p.Actions {
		n += a.Len()
	}
	n += p.Data.Len()
	// if n < 72 { return 72 }
	return
}

func (p *PacketOut) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(p.Len()))
	var b []byte
	n := 0

	p.Header.Length = p.Len()
	if b, err = p.Header.MarshalBinary(); err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)

	binary.BigEndian.PutUint32(data[n:], p.BufferId)
	n += 4
	binary.BigEndian.PutUint32(data[n:], p.InPort)
	n += 4
	binary.BigEndian.PutUint16(data[n:], p.ActionsLen)
	n += 2
	n += 6 // for pad

	for _, a := range p.Actions {
		if b, err = a.MarshalBinary(); err != nil {
			return
		}
		copy(data[n:], b)
		n += len(b)
	}

	if b, err = p.Data.MarshalBinary(); err != nil {
		return
	}
	copy(data[n:], b)
	n += len(b)
	return
}

func (p *PacketOut) UnmarshalBinary(data []byte) error {
	if err := p.Header.UnmarshalBinary(data); err != nil {
		return err
	}
	n := p.Header.Len()

	p.BufferId = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.InPort = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.ActionsLen = binary.BigEndian.Uint16(data[n:])
	n += 2

	n += 6 // for pad

	for n < (n + p.ActionsLen) {
		a, err := DecodeAction(data[n:])
		if err != nil {
			return err
		}
		p.Actions = append(p.Actions, a)
		n += a.Len()
	}

	return p.Data.UnmarshalBinary(data[n:])
}

// ofp_packet_in 1.3
type PacketIn struct {
	common.Header
	BufferId uint32
	TotalLen uint16
	Reason   uint8
	TableId  uint8
	Cookie   uint64
	Match    Match
	pad      []uint8
	Data     protocol.Ethernet
}

func NewPacketIn() *PacketIn {
	p := new(PacketIn)
	p.Header = NewOfp13Header()
	p.Header.Type = Type_PacketIn
	p.BufferId = 0xffffffff
	p.Reason = 0
	p.TableId = 0
	p.Cookie = 0
	p.Match = *NewMatch()
	return p
}

func (p *PacketIn) Len() (n uint16) {
	n += p.Header.Len()
	n += 16
	n += p.Match.Len()
	n += 2
	n += p.Data.Len()
	return
}

func (p *PacketIn) MarshalBinary() (data []byte, err error) {
	if data, err = p.Header.MarshalBinary(); err != nil {
		return
	}

	b := make([]byte, 16)
	n := 0
	binary.BigEndian.PutUint32(b, p.BufferId)
	n += 4
	binary.BigEndian.PutUint16(b[n:], p.TotalLen)
	n += 2
	b[n] = p.Reason
	n += 1
	b[n] = p.TableId
	n += 1
	binary.BigEndian.PutUint64(b, p.Cookie)
	n += 8
	data = append(data, b...)

	if b, err = p.Match.MarshalBinary(); err != nil {
		return
	}
	data = append(data, b...)

	b = make([]byte, 2)
	copy(b[0:], p.pad)
	data = append(data, b...)

	if b, err = p.Data.MarshalBinary(); err != nil {
		return
	}
	data = append(data, b...)
	return
}

func (p *PacketIn) UnmarshalBinary(data []byte) error {
	if err := p.Header.UnmarshalBinary(data); err != nil {
		return err
	}
	n := p.Header.Len()

	p.BufferId = binary.BigEndian.Uint32(data[n:])
	n += 4
	p.TotalLen = binary.BigEndian.Uint16(data[n:])
	n += 2
	p.Reason = data[n]
	n += 1
	p.TableId = data[n]
	n += 1
	p.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 8

	if err := p.Match.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	n += p.Match.Len()

	copy(p.pad, data[n:])
	n += 2

	return p.Data.UnmarshalBinary(data[n:])
}

// ofp_packet_in_reason 1.3
const (
	R_NO_MATCH    = iota /* No matching flow (table-miss flow entry). */
	R_ACTION             /* Action explicitly output to controller. */
	R_INVALID_TTL        /* Packet has invalid TTL */
	R_ACTION_SET         /* Output to controller in action set */
	R_GROUP              /* Output to controller in group bucket */
	R_PACKET_OUT         /* Output to controller in packet-out */
)

// nx_continuation_prop_type
const (
	NXCPT_BRIDGE      = 0x8000
	NXCPT_STACK       = 0x8001
	NXCPT_MIRRORS     = 0x8002
	NXCPT_CONNTRACKED = 0x8003
	NXCPT_TABLE_ID    = 0x8004
	NXCPT_COOKIE      = 0x8005
	NXCPT_ACTIONS     = 0x8006
	NXCPT_ACTION_SET  = 0x8007
	NXCPT_ODP_PORT    = 0x8008
)

type ContinuationPropBridge struct {
	*PropHeader /* Type: NXCPT_BRIDGE */
	Bridge      [4]uint32
	pad         [4]uint8
}

func (p *ContinuationPropBridge) Len() (n uint16) {
	return p.PropHeader.Len() + 20
}

func (p *ContinuationPropBridge) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 16
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(data[n:], p.Bridge[i])
		n += 4
	}
	n += 4
	return
}

func (p *ContinuationPropBridge) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationProp* message")
	}
	n += int(p.PropHeader.Len())
	for i := 0; i < 4; i++ {
		p.Bridge[i] = binary.BigEndian.Uint32(data[n:])
		n += 4
	}
	n += 4
	return nil
}

type ContinuationPropStack struct {
	*PropHeader /* Type: NXCPT_STACK */
	Stack       []uint8
	pad         []uint8
}

func (p *ContinuationPropStack) Len() (n uint16) {
	n = p.PropHeader.Len() + uint16(len(p.Stack))

	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *ContinuationPropStack) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + uint16(len(p.Stack))
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	copy(data[n:], p.Stack)
	n += len(p.Stack)
	return
}

func (p *ContinuationPropStack) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationProp* message")
	}
	n += int(p.PropHeader.Len())
	for _, eachStack := range p.Stack {
		data[n] = eachStack
		n++
	}
	return nil
}

type ContinuationPropMirrors struct {
	*PropHeader /* Type: NXCPT_MIRRORS */
	Mirrors     uint32
}

func (p *ContinuationPropMirrors) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *ContinuationPropMirrors) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 4
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	binary.BigEndian.PutUint32(data[n:], p.Mirrors)
	n += 4
	return
}

func (p *ContinuationPropMirrors) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationProp* message")
	}
	n += int(p.PropHeader.Len())
	p.Mirrors = binary.BigEndian.Uint32(data[n:])
	n += 4
	return nil
}

type ContinuationPropConntracked struct {
	*PropHeader /* Type: NXCPT_CONNTRACKED */
	pad         [4]uint8
}

func (p *ContinuationPropConntracked) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *ContinuationPropConntracked) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len()
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	n += 4
	return
}

func (p *ContinuationPropConntracked) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationProp* message")
	}
	n += int(p.PropHeader.Len())
	n += 4
	return nil
}

type ContinuationPropTableID struct {
	*PropHeader /* Type: NXCPT_TABLE_ID */
	TableID     uint8
	pad         [3]uint8
}

func (p *ContinuationPropTableID) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *ContinuationPropTableID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 1
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	data[n] = p.TableID
	n += 1
	n += 3
	return
}

func (p *ContinuationPropTableID) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationProp* message")
	}
	n += int(p.PropHeader.Len())
	p.TableID = data[n]
	n += 1
	n += 3
	return nil
}

type ContinuationPropCookie struct {
	*PropHeader /* Type: NXCPT_COOKIE */
	Cookie      uint64
	pad         [4]uint8
}

func (p *ContinuationPropCookie) Len() (n uint16) {
	return p.PropHeader.Len() + 12
}

func (p *ContinuationPropCookie) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 8
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	binary.BigEndian.PutUint64(data[n:], p.Cookie)
	n += 4
	return
}

func (p *ContinuationPropCookie) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationProp* message")
	}
	n += int(p.PropHeader.Len())
	p.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 4
	return nil
}

type ContinuationPropActions struct {
	*PropHeader /* Type: NXCPT_ACTIONS */
	Actions     []Action
}

func (p *ContinuationPropActions) Len() (n uint16) {
	n = p.PropHeader.Len()
	for _, action := range p.Actions {
		n += action.Len()
	}
	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *ContinuationPropActions) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.Len()
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	for _, action := range p.Actions {
		b, err = action.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(action.Len())
	}
	return
}

func (p *ContinuationPropActions) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	for n < int(p.Length) {
		act, err := DecodeAction(data[n:])
		if err != nil {
			return errors.New("failed to decode actions")
		}
		p.Actions = append(p.Actions, act)
		n += int(act.Len())
	}
	return nil
}

type ContinuationPropActionSet struct {
	*PropHeader /* Type: NXCPT_ACTION_SET */
	ActionSet   []Action
}

func (p *ContinuationPropActionSet) Len() (n uint16) {
	n = p.PropHeader.Len()
	for _, action := range p.ActionSet {
		n += action.Len()
	}
	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *ContinuationPropActionSet) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.Len()
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	for _, action := range p.ActionSet {
		b, err = action.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(action.Len())
	}
	return
}

func (p *ContinuationPropActionSet) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	for n < int(p.Length) {
		act, err := DecodeAction(data[n:])
		if err != nil {
			return errors.New("failed to decode actions")
		}
		p.ActionSet = append(p.ActionSet, act)
		n += int(act.Len())
	}
	return nil
}

type ContinuationPropOdpPort struct {
	*PropHeader /* Type: NXCPT_ODP_PORT */
	OdpPort     uint32
}

func (p *ContinuationPropOdpPort) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *ContinuationPropOdpPort) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 4
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	binary.BigEndian.PutUint32(data[n:], p.OdpPort)
	n += 4
	return
}

func (p *ContinuationPropOdpPort) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full ContinuationProp* message")
	}
	n += int(p.PropHeader.Len())
	p.OdpPort = binary.BigEndian.Uint32(data[n:])
	n += 4
	return nil
}

// Decode Continuation Property types.
func DecodeContinuationProp(data []byte) (Property, error) {
	t := binary.BigEndian.Uint16(data[:2])
	var p Property
	switch t {
	case NXCPT_BRIDGE:
		p = new(ContinuationPropBridge)
	case NXCPT_STACK:
		p = new(ContinuationPropStack)
	case NXCPT_MIRRORS:
		p = new(ContinuationPropMirrors)
	case NXCPT_CONNTRACKED:
		p = new(ContinuationPropConntracked)
	case NXCPT_TABLE_ID:
		p = new(ContinuationPropTableID)
	case NXCPT_COOKIE:
		p = new(ContinuationPropCookie)
	case NXCPT_ACTIONS:
		p = new(ContinuationPropActions)
	case NXCPT_ACTION_SET:
		p = new(ContinuationPropActionSet)
	case NXCPT_ODP_PORT:
		p = new(ContinuationPropOdpPort)
	}
	err := p.UnmarshalBinary(data)
	if err != nil {
		return p, err
	}
	return p, nil
}

// nx_packet_in2_prop_type
const (
	/* Packet. */
	NXPINT_PACKET    = iota /* Raw packet data. */
	NXPINT_FULL_LEN         /* ovs_be32: Full packet len, if truncated. */
	NXPINT_BUFFER_ID        /* ovs_be32: Buffer ID, if buffered. */

	/* Information about the flow that triggered the packet-in. */
	NXPINT_TABLE_ID /* uint8_t: Table ID. */
	NXPINT_COOKIE   /* ovs_be64: Flow cookie. */

	/* Other. */
	NXPINT_REASON       /* uint8_t, one of OFPR_*. */
	NXPINT_METADATA     /* NXM or OXM for metadata fields. */
	NXPINT_USERDATA     /* From NXAST_CONTROLLER2 userdata. */
	NXPINT_CONTINUATION /* Private data for continuing processing. */
)

type PacketIn2PropPacket struct {
	*PropHeader
	Packet []byte
	pad    []uint8
}

func (p *PacketIn2PropPacket) Len() (n uint16) {
	n = p.PropHeader.Len()
	n += uint16(len(p.Packet))

	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *PacketIn2PropPacket) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + uint16(len(p.Packet))
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	copy(data[n:], p.Packet)
	n += len(p.Packet)
	return
}

func (p *PacketIn2PropPacket) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	p.Packet = data[n:p.Length]
	return nil
}

type PacketIn2PropFullLen struct {
	*PropHeader /* Type: NXPINT_FULL_LEN */
	FullLen     uint32
}

func (p *PacketIn2PropFullLen) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropFullLen) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 4
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	binary.BigEndian.PutUint32(data[n:], p.FullLen)
	n += 4
	return
}

func (p *PacketIn2PropFullLen) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	p.FullLen = binary.BigEndian.Uint32(data[n:])
	n += 4
	return nil
}

type PacketIn2PropBufferID struct {
	*PropHeader /* Type: NXPINT_BUFFER_ID */
	BufferID    uint32
}

func (p *PacketIn2PropBufferID) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropBufferID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 4
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	binary.BigEndian.PutUint32(data[n:], p.BufferID)
	n += 4
	return
}

func (p *PacketIn2PropBufferID) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	p.BufferID = binary.BigEndian.Uint32(data[n:])
	n += 4
	return nil
}

type PacketIn2PropTableID struct {
	*PropHeader /* Type: NXPINT_TABLE_ID */
	TableID     uint8
	pad         [3]uint8
}

func (p *PacketIn2PropTableID) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropTableID) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 1
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	data[n] = p.TableID
	n += 1
	n += 3
	return
}

func (p *PacketIn2PropTableID) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	p.TableID = data[n]
	n += 1
	n += 3
	return nil
}

type PacketIn2PropCookie struct {
	*PropHeader /* Type: NXPINT_COOKIE */
	Cookie      uint64
	pad         [4]uint8
}

func (p *PacketIn2PropCookie) Len() (n uint16) {
	return p.PropHeader.Len() + 12
}

func (p *PacketIn2PropCookie) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 8
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	binary.BigEndian.PutUint64(data[n:], p.Cookie)
	n += 4
	return
}

func (p *PacketIn2PropCookie) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	p.Cookie = binary.BigEndian.Uint64(data[n:])
	n += 4
	return nil
}

type PacketIn2PropReason struct {
	*PropHeader /* Type: NXPINT_COOKIE */
	Reason      uint8
	pad         [3]uint8
}

func (p *PacketIn2PropReason) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropReason) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 1
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	data[n] = p.Reason
	n += 1
	n += 3
	return
}

func (p *PacketIn2PropReason) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	p.Reason = data[n]
	n += 1
	n += 3
	return nil
}

type PacketIn2PropMetadata struct {
	*PropHeader /* Type: NXPINT_METADATA */
	Match       Match
	pad         [4]uint8
}

func (p *PacketIn2PropMetadata) Len() (n uint16) {
	return p.PropHeader.Len() + p.Match.Len() + 4
}

func (p *PacketIn2PropMetadata) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + p.Match.Len()
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())

	b, err = p.Match.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.Match.Len())

	n += 4
	return
}

func (p *PacketIn2PropMetadata) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())

	if err = p.Match.UnmarshalBinary(data[n:]); err != nil {
		return err
	}
	n += int(p.Match.Len())

	n += 4
	return nil
}

type PacketIn2PropUserdata struct {
	*PropHeader /* Type: NXPINT_USERDATA */
	Userdata    uint8
	pad         [3]uint8
}

func (p *PacketIn2PropUserdata) Len() (n uint16) {
	return p.PropHeader.Len() + 4
}

func (p *PacketIn2PropUserdata) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.PropHeader.Len() + 1
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	data[n] = p.Userdata
	n += 1
	n += 3
	return
}

func (p *PacketIn2PropUserdata) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	p.Userdata = data[n]
	n += 1
	n += 3
	return nil
}

type PacketIn2PropContinuation struct {
	*PropHeader /* Type: NXPINT_CONTINUATION */
	pad1        [4]uint8
	props       []Property
}

func (p *PacketIn2PropContinuation) Len() (n uint16) {
	n = p.PropHeader.Len() + 4
	for _, prop := range p.props {
		n += prop.Len()
	}
	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *PacketIn2PropContinuation) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.Len()
	var b []byte
	n := 0
	b, err = p.PropHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.PropHeader.Len())
	for _, prop := range p.props {
		b, err = prop.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(prop.Len())
	}
	return
}

func (p *PacketIn2PropContinuation) UnmarshalBinary(data []byte) error {
	p.PropHeader = new(PropHeader)
	n := 0
	err := p.PropHeader.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2Prop* message")
	}
	n += int(p.PropHeader.Len())
	for n < int(p.Length) {
		prop, err := DecodeContinuationProp(data[n:])
		if err != nil {
			return errors.New("failed to decode property")
		}
		p.props = append(p.props, prop)
		n += int(prop.Len())
	}
	return nil
}

// Decode PacketIn2 Property types.
func DecodePacketIn2Prop(data []byte) (Property, error) {
	t := binary.BigEndian.Uint16(data[:2])
	var p Property
	switch t {
	case NXPINT_PACKET:
		p = new(PacketIn2PropPacket)
	case NXPINT_FULL_LEN:
		p = new(PacketIn2PropFullLen)
	case NXPINT_BUFFER_ID:
		p = new(PacketIn2PropBufferID)
	case NXPINT_TABLE_ID:
		p = new(PacketIn2PropTableID)
	case NXPINT_COOKIE:
		p = new(PacketIn2PropCookie)
	case NXPINT_REASON:
		p = new(PacketIn2PropReason)
	case NXPINT_METADATA:
		p = new(PacketIn2PropMetadata)
	case NXPINT_USERDATA:
		p = new(PacketIn2PropUserdata)
	case NXPINT_CONTINUATION:
		p = new(PacketIn2PropContinuation)
	}
	err := p.UnmarshalBinary(data)
	if err != nil {
		return p, err
	}
	return p, nil
}

type PacketIn2 struct {
	common.Header
	Props []Property
	Data  protocol.Ethernet
}

func (p *PacketIn2) Len() (n uint16) {
	n = p.Header.Len()
	for _, prop := range p.Props {
		n += prop.Len()
	}
	n += p.Data.Len()
	// Round it to closest multiple of 8
	return ((n + 7) / 8) * 8
}

func (p *PacketIn2) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	p.Length = p.Len()
	var b []byte
	n := 0
	b, err = p.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	n += int(p.Header.Len())
	for _, prop := range p.Props {
		b, err = prop.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], b)
		n += int(prop.Len())
	}
	b, err = p.Data.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[n:], b)
	return
}

func (p *PacketIn2) UnmarshalBinary(data []byte) error {
	n := 0
	err := p.Header.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	if len(data) < int(p.Length) {
		return errors.New("the []byte is too short to unmarshal a full PacketIn2 message")
	}
	n += int(p.Header.Len())
	for n < int(p.Length) {
		prop, err := DecodePacketIn2Prop(data[n:])
		if err != nil {
			return errors.New("failed to decode property")
		}
		p.Props = append(p.Props, prop)
		n += int(prop.Len())
	}
	err = p.Data.UnmarshalBinary(data[n:])
	if err != nil {
		return err
	}
	return nil
}

func NewPacketIn2() *PacketIn2 {
	p := new(PacketIn2)
	p.Header = NewOfp13Header()
	p.Header.Type = Type_PacketIn2
	return p
}

func NewConfigRequest() *common.Header {
	h := NewOfp13Header()
	h.Type = Type_GetConfigRequest
	return &h
}

// ofp_config_flags 1.3
const (
	C_FRAG_NORMAL = 0
	C_FRAG_DROP   = 1
	C_FRAG_REASM  = 2
	C_FRAG_MASK   = 3
)

// ofp_switch_config 1.3
type SwitchConfig struct {
	common.Header
	Flags       uint16 // OFPC_* flags
	MissSendLen uint16
}

func NewSetConfig() *SwitchConfig {
	c := new(SwitchConfig)
	c.Header = NewOfp13Header()
	c.Header.Type = Type_SetConfig
	c.Flags = 0
	c.MissSendLen = 0
	return c
}

func (c *SwitchConfig) Len() (n uint16) {
	n = c.Header.Len()
	n += 4
	return
}

func (c *SwitchConfig) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(c.Len()))
	var bytes []byte
	next := 0

	c.Header.Length = c.Len()
	if bytes, err = c.Header.MarshalBinary(); err != nil {
		return
	}
	copy(data[next:], bytes)
	next += len(bytes)
	binary.BigEndian.PutUint16(data[next:], c.Flags)
	next += 2
	binary.BigEndian.PutUint16(data[next:], c.MissSendLen)
	next += 2
	return
}

func (c *SwitchConfig) UnmarshalBinary(data []byte) error {
	var err error
	next := 0

	err = c.Header.UnmarshalBinary(data[next:])
	next += int(c.Header.Len())
	c.Flags = binary.BigEndian.Uint16(data[next:])
	next += 2
	c.MissSendLen = binary.BigEndian.Uint16(data[next:])
	next += 2
	return err
}

// BEGIN: ofp13 - 7.4.4
// ofp_error_msg 1.3
type ErrorMsg struct {
	common.Header
	Type uint16
	Code uint16
	Data util.Buffer
}

func NewErrorMsg() *ErrorMsg {
	e := new(ErrorMsg)
	e.Data = *util.NewBuffer(make([]byte, 0))
	return e
}

func (e *ErrorMsg) Len() (n uint16) {
	n = e.Header.Len()
	n += 2
	n += 2
	n += e.Data.Len()
	return
}

func (e *ErrorMsg) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(e.Len()))
	var bytes []byte
	next := 0

	if bytes, err = e.Header.MarshalBinary(); err != nil {
		return
	}
	copy(data[next:], bytes)
	next += len(bytes)
	binary.BigEndian.PutUint16(data[next:], e.Type)
	next += 2
	binary.BigEndian.PutUint16(data[next:], e.Code)
	next += 2
	if bytes, err = e.Data.MarshalBinary(); err != nil {
		return
	}
	copy(data[next:], bytes)
	next += len(bytes)
	return
}

func (e *ErrorMsg) UnmarshalBinary(data []byte) error {
	next := 0
	e.Header.UnmarshalBinary(data[next:])
	next += int(e.Header.Len())
	e.Type = binary.BigEndian.Uint16(data[next:])
	next += 2
	e.Code = binary.BigEndian.Uint16(data[next:])
	next += 2
	e.Data.UnmarshalBinary(data[next:])
	next += int(e.Data.Len())
	return nil
}

// ofp_error_type 1.3
const (
	ET_HELLO_FAILED          = 0      /* Hello protocol failed. */
	ET_BAD_REQUEST           = 1      /* Request was not understood. */
	ET_BAD_ACTION            = 2      /* Error in action description. */
	ET_BAD_INSTRUCTION       = 3      /* Error in instruction list. */
	PET_BAD_MATCH            = 4      /* Error in match. */
	ET_FLOW_MOD_FAILED       = 5      /* Problem modifying flow entry. */
	ET_GROUP_MOD_FAILED      = 6      /* Problem modifying group entry. */
	ET_PORT_MOD_FAILED       = 7      /* Port mod request failed. */
	ET_TABLE_MOD_FAILED      = 8      /* Table mod request failed. */
	ET_QUEUE_OP_FAILED       = 9      /* Queue operation failed. */
	ET_ROLE_REQUEST_FAILED   = 11     /* Controller Role request failed. */
	ET_METER_MOD_FAILED      = 12     /* Error in meter. */
	ET_TABLE_FEATURES_FAILED = 13     /* Setting table features failed. */
	ET_EXPERIMENTER          = 0xffff /* Experimenter error messages. */
)

// ofp_hello_failed_code 1.3
const (
	HFC_INCOMPATIBLE = iota
	HFC_EPERM
)

// ofp_bad_request_code 1.3
const (
	BRC_BAD_VERSION = iota
	BRC_BAD_TYPE
	BRC_BAD_MULTIPART
	BRC_BAD_EXPERIMENTER

	BRC_BAD_EXP_TYPE
	BRC_EPERM
	BRC_BAD_LEN
	BRC_BUFFER_EMPTY
	BRC_BUFFER_UNKNOWN
	BRC_BAD_TABLE_ID
	BRC_IS_SLAVE
	BRC_BAD_PORT
	BRC_BAD_PACKET
	BRC_MULTIPART_BUFFER_OVERFLOW
)

// ofp_bad_action_code 1.3
const (
	BAC_BAD_TYPE = iota
	BAC_BAD_LEN
	BAC_BAD_EXPERIMENTER
	BAC_BAD_EXP_TYPE
	BAC_BAD_OUT_PORT
	BAC_BAD_ARGUMENT
	BAC_EPERM
	BAC_TOO_MANY
	BAC_BAD_QUEUE
	BAC_BAD_OUT_GROUP
	BAC_MATCH_INCONSISTENT
	BAC_UNSUPPORTED_ORDER
	BAC_BAD_TAG
	BAC_BAD_SET_TYPE
	BAC_BAD_SET_LEN
	BAC_BAD_SET_ARGUMENT
)

// ofp_bad_instruction_code 1.3
const (
	BIC_UNKNOWN_INST        = 0 /* Unknown instruction. */
	BIC_UNSUP_INST          = 1 /* Switch or table does not support the instruction. */
	BIC_BAD_TABLE_ID        = 2 /* Invalid Table-ID specified. */
	BIC_UNSUP_METADATA      = 3 /* Metadata value unsupported by datapath. */
	BIC_UNSUP_METADATA_MASK = 4 /* Metadata mask value unsupported by datapath. */
	BIC_BAD_EXPERIMENTER    = 5 /* Unknown experimenter id specified. */
	BIC_BAD_EXP_TYPE        = 6 /* Unknown instruction for experimenter id. */
	BIC_BAD_LEN             = 7 /* Length problem in instructions. */
	BIC_EPERM               = 8 /* Permissions error. */
)

// ofp_flow_mod_failed_code 1.3
const (
	FMFC_UNKNOWN      = 0 /* Unspecified error. */
	FMFC_TABLE_FULL   = 1 /* Flow not added because table was full. */
	FMFC_BAD_TABLE_ID = 2 /* Table does not exist */
	FMFC_OVERLAP      = 3 /* Attempted to add overlapping flow with CHECK_OVERLAP flag set. */
	FMFC_EPERM        = 4 /* Permissions error. */
	FMFC_BAD_TIMEOUT  = 5 /* Flow not added because of unsupported idle/hard timeout. */
	FMFC_BAD_COMMAND  = 6 /* Unsupported or unknown command. */
	FMFC_BAD_FLAGS    = 7 /* Unsupported or unknown flags. */
)

// ofp_bad_match_code 1.3
const (
	BMC_BAD_TYPE         = 0  /* Unsupported match type specified by the match */
	BMC_BAD_LEN          = 1  /* Length problem in match. */
	BMC_BAD_TAG          = 2  /* Match uses an unsupported tag/encap. */
	BMC_BAD_DL_ADDR_MASK = 3  /* Unsupported datalink addr mask - switch does not support arbitrary datalink address mask. */
	BMC_BAD_NW_ADDR_MASK = 4  /* Unsupported network addr mask - switch does not support arbitrary network address mask. */
	BMC_BAD_WILDCARDS    = 5  /* Unsupported combination of fields masked or omitted in the match. */
	BMC_BAD_FIELD        = 6  /* Unsupported field type in the match. */
	BMC_BAD_VALUE        = 7  /* Unsupported value in a match field. */
	BMC_BAD_MASK         = 8  /* Unsupported mask specified in the match, field is not dl-address or nw-address. */
	BMC_BAD_PREREQ       = 9  /* A prerequisite was not met. */
	BMC_DUP_FIELD        = 10 /* A field type was duplicated. */
	BMC_EPERM            = 11 /* Permissions error. */
)

// ofp_group_mod_failed_code 1.3
const (
	GMFC_GROUP_EXISTS         = 0  /* Group not added because a group ADD attempted to replace an already-present group. */
	GMFC_INVALID_GROUP        = 1  /* Group not added because Group specified is invalid. */
	GMFC_WEIGHT_UNSUPPORTED   = 2  /* Switch does not support unequal load 105 ➞ 2013; The Open Networking Foundation OpenFlow Switch Specification Version 1.3.3 sharing with select groups. */
	GMFC_OUT_OF_GROUPS        = 3  /* The group table is full. */
	GMFC_OUT_OF_BUCKETS       = 4  /* The maximum number of action buckets for a group has been exceeded. */
	GMFC_CHAINING_UNSUPPORTED = 5  /* Switch does not support groups that forward to groups. */
	GMFC_WATCH_UNSUPPORTED    = 6  /* This group cannot watch the watch_port or watch_group specified. */
	GMFC_LOOP                 = 7  /* Group entry would cause a loop. */
	GMFC_UNKNOWN_GROUP        = 8  /* Group not modified because a group MODIFY attempted to modify a non-existent group. */
	GMFC_CHAINED_GROUP        = 9  /* Group not deleted because another group is forwarding to it. */
	GMFC_BAD_TYPE             = 10 /* Unsupported or unknown group type. */
	GMFC_BAD_COMMAND          = 11 /* Unsupported or unknown command. */
	GMFC_BAD_BUCKET           = 12 /* Error in bucket. */
	GMFC_BAD_WATCH            = 13 /* Error in watch port/group. */
	GMFC_EPERM                = 14 /* Permissions error. */
)

// ofp_port_mod_failed_code 1.0
const (
	PMFC_BAD_PORT = iota
	PMFC_BAD_HW_ADDR
	PMFC_BAD_CONFIG
	PMFC_BAD_ADVERTISE
	PMFC_EPERM
)

// ofp_table_mod_failed_code
const (
	TMFC_BAD_TABLE  = 0 /* Specified table does not exist. */
	TMFC_BAD_CONFIG = 1 /* Specified config is invalid. */
	TMFC_EPERM      = 2 /* Permissions error. */
)

// ofp_queue_op_failed_code 1.0
const (
	QOFC_BAD_PORT = iota
	QOFC_BAD_QUEUE
	QOFC_EPERM
)

// END: ofp13 - 7.4.4
// END: ofp13 - 7.4

type SwitchFeatures struct {
	common.Header
	DPID         net.HardwareAddr // Size 8
	Buffers      uint32
	NumTables    uint8
	AuxilaryId   uint8
	pad          []uint8 // Size 2
	Capabilities uint32
	Actions      uint32

	Ports []PhyPort
}

// FeaturesRequest constructor
func NewFeaturesRequest() *common.Header {
	req := NewOfp13Header()
	req.Type = Type_FeaturesRequest
	return &req
}

// FeaturesReply constructor
func NewFeaturesReply() *SwitchFeatures {
	res := new(SwitchFeatures)
	res.Header = NewOfp13Header()
	res.Header.Type = Type_FeaturesReply
	res.DPID = make([]byte, 8)
	res.pad = make([]byte, 2)
	res.Ports = make([]PhyPort, 0)
	return res
}

func (s *SwitchFeatures) Len() (n uint16) {
	n = s.Header.Len()
	n += uint16(len(s.DPID))
	n += 16
	for _, p := range s.Ports {
		n += p.Len()
	}
	return
}

func (s *SwitchFeatures) MarshalBinary() (data []byte, err error) {
	data = make([]byte, int(s.Len()))
	var bytes []byte
	next := 0

	s.Header.Length = s.Len()
	if bytes, err = s.Header.MarshalBinary(); err != nil {
		return
	}
	copy(data[next:], bytes)
	next += len(bytes)
	binary.BigEndian.PutUint32(data[next:], s.Buffers)
	next += 4
	data[next] = s.NumTables
	next += 1
	data[next] = s.AuxilaryId
	next += 1
	copy(data[next:], s.pad)
	next += len(s.pad)
	binary.BigEndian.PutUint32(data[next:], s.Capabilities)
	next += 4
	binary.BigEndian.PutUint32(data[next:], s.Actions)
	next += 4

	for _, p := range s.Ports {
		if bytes, err = p.MarshalBinary(); err != nil {
			return
		}
		copy(data[next:], bytes)
		next += len(bytes)
	}
	return
}

func (s *SwitchFeatures) UnmarshalBinary(data []byte) error {
	var err error
	next := 0

	err = s.Header.UnmarshalBinary(data[next:])
	next = int(s.Header.Len())
	copy(s.DPID, data[next:])
	next += len(s.DPID)
	s.Buffers = binary.BigEndian.Uint32(data[next:])
	next += 4
	s.NumTables = data[next]
	next += 1
	s.AuxilaryId = data[next]
	next += 1
	copy(s.pad, data[next:])
	next += len(s.pad)
	s.Capabilities = binary.BigEndian.Uint32(data[next:])
	next += 4
	s.Actions = binary.BigEndian.Uint32(data[next:])
	next += 4

	for next < len(data) {
		p := NewPhyPort()
		err = p.UnmarshalBinary(data[next:])
		next += int(p.Len())
	}
	return err
}

// ofp_capabilities 1.3
const (
	C_FLOW_STATS   = 1 << 0
	C_TABLE_STATS  = 1 << 1
	C_PORT_STATS   = 1 << 2
	C_GROUP_STATS  = 1 << 3
	C_RESERVED     = 1 << 4
	C_IP_REASM     = 1 << 5
	C_QUEUE_STATS  = 1 << 6
	C_PORT_BLOCKED = 1 << 8
)

// ofp_vendor 1.3
type VendorHeader struct {
	Header           common.Header /*Type OFPT_VENDOR*/
	Vendor           uint32
	ExperimenterType uint32
	VendorData       util.Message
}

func (v *VendorHeader) Len() (n uint16) {
	length := uint16(16)
	if v.VendorData != nil {
		length += v.VendorData.Len()
	}
	return length
}

func (v *VendorHeader) MarshalBinary() (data []byte, err error) {
	v.Header.Length = v.Len()
	data = make([]byte, v.Len())
	b, err := v.Header.MarshalBinary()
	n := 0
	copy(data[n:], b)
	n += len(b)
	binary.BigEndian.PutUint32(data[n:], v.Vendor)
	n += 4
	binary.BigEndian.PutUint32(data[n:], v.ExperimenterType)
	n += 4
	if v.VendorData != nil {
		vd, err := v.VendorData.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[n:], vd)
		n += len(vd)
	}
	return
}

func (v *VendorHeader) UnmarshalBinary(data []byte) error {
	if len(data) < 16 {
		return errors.New("The []byte the wrong size to unmarshal an " +
			"VendorHeader message.")
	}
	v.Header.UnmarshalBinary(data)
	n := int(v.Header.Len())
	v.Vendor = binary.BigEndian.Uint32(data[n:])
	n += 4
	v.ExperimenterType = binary.BigEndian.Uint32(data[n:])
	n += 4
	if n < int(v.Header.Length) {
		var err error
		v.VendorData, err = decodeVendorData(v.ExperimenterType, data[n:v.Header.Length])
		if err != nil {
			return err
		}
	}
	return nil
}

type Property interface {
	Header() *PropHeader
	util.Message
}

/* Generic OpenFlow property header, as used by various messages in OF1.3+, and
 * especially in OF1.4.
 *
 * The OpenFlow specs prefer to define a new structure with a specialized name
 * each time this property structure comes up: struct
 * ofp_port_desc_prop_header, struct ofp_controller_status_prop_header, struct
 * ofp_table_mod_prop_header, and more.  They're all the same, so it's easier
 * to unify them.
 */
type PropHeader struct {
	Type   uint16
	Length uint16
}

func (p *PropHeader) Header() *PropHeader {
	return p
}

func (p *PropHeader) Len() (n uint16) {
	return 4
}

func (p *PropHeader) MarshalBinary() (data []byte, err error) {
	data = make([]byte, p.Len())
	binary.BigEndian.PutUint16(data[:2], p.Type)
	binary.BigEndian.PutUint16(data[2:4], p.Length)
	return
}

func (p *PropHeader) UnmarshalBinary(data []byte) error {
	if len(data) < int(p.Len()) {
		return errors.New("the []byte the wrong size to unmarshal an " +
			"PropHeader message")
	}
	p.Type = binary.BigEndian.Uint16(data[:2])
	p.Length = binary.BigEndian.Uint16(data[2:4])
	return nil
}
