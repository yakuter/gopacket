// Copyright 2019, The GoPacket Authors, All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
//******************************************************************************

package layers

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/gopacket"
)

//******************************************************************************
//
// DNP3 Decoding Layer
// ------------------------------------------
// This file provides a GoPacket decoding layer for DNP3.
//
//******************************************************************************

// DNP3 is the struct for storing DNP3 packet headers.

const (
	MIN_HEADER_LENGTH = 10
	START_FIELD       = 0x0564
)

var FCodes = map[byte]string{
	0:   "Confirm",
	1:   "Read",
	2:   "Write",
	3:   "Select",
	4:   "Operate",
	5:   "Direct Operate",
	6:   "Direct Operate No ACK",
	7:   "Immediate Freeze",
	8:   "Immediate Freeze No ACK",
	9:   "Freeze and Clear",
	10:  "Freeze and Clear No ACK",
	11:  "Freeze With Time",
	12:  "Freeze With Time No ACK",
	13:  "Cold Restart",
	14:  "Warm Restart",
	15:  "Initialize Data",
	16:  "Initialize Application",
	17:  "Start Application",
	18:  "Stop Application",
	19:  "Save Configuration",
	20:  "Enable Spontaneous Msg",
	21:  "Disable Spontaneous Msg",
	22:  "Assign Classes",
	23:  "Delay Measurement",
	24:  "Record Current Time",
	25:  "Open File",
	26:  "Close File",
	27:  "Delete File",
	28:  "Get File Info",
	29:  "Authenticate File",
	30:  "Abort File",
	31:  "Activate Config",
	32:  "Authentication Request",
	33:  "Authentication Error",
	129: "Response",
	130: "Unsolicited Response",
	131: "Authentication Response",
}

// "-" Reserved or Obsolete
var PfCodes = map[byte]string{
	0:  "Reset of Remote Link", // 0x10
	1:  "Reset of User Process",
	2:  "Test Function For Link", // 0x12
	3:  "User Data",              // 0x13
	4:  "Unconfirmed User Data",  // 0x14
	5:  "-",
	6:  "-",
	7:  "-",
	8:  "-",
	9:  "Request Link Status", // 0x19
	10: "-",
	11: "-",
	12: "-",
	13: "-",
	14: "-",
	15: "-",
}

var SfCodes = map[byte]string{
	0:  "ACK", // 0x00
	1:  "NAK", // 0x01
	2:  "-",
	3:  "-",
	4:  "-",
	5:  "-",
	6:  "-",
	7:  "-",
	8:  "-",
	9:  "-",
	10: "-",
	11: "Status of Link", // 0x0B
	12: "-",
	13: "-",
	14: "Link Service Not Functioning",
	15: "Link Service Not Used or Implemented", // 0x0F
}

/***************************************************************************/
/* Application Layer Internal Indication (IIN) bits */
/* 2 Bytes, message formatting: [First Octet] | [Second Octet] */
/***************************************************************************/
var IINCodes = map[string]string{
	/* Octet 1 */
	"0x0100": "Broadcast message rx'd",
	"0x0200": "Class 1 Data Available",
	"0x0400": "Class 2 Data Available",
	"0x0800": "Class 3 Data Available",
	"0x1000": "Time Sync Req'd from Master",
	"0x2000": "Outputs in Local Mode",
	"0x4000": "Device Trouble",
	"0x8000": "Device Restart",

	/* Octet 2 */
	"0x0001": "Function code not implemented",
	"0x0002": "Requested Objects Unknown",
	"0x0004": "Parameters Invalid or Out of Range",
	"0x0008": "Event Buffer Overflow",
	"0x0010": "Operation Already Executing",
	"0x0020": "Device Configuration Corrupt",
	"0x0040": "Reserved",
	"0x0080": "Reserved",
}

/***************************************************************************/
/* Application Layer Object Prefix codes bits */
/***************************************************************************/
var ObjPrefixCodes = map[byte]string{
	0: "Objects packed without a prefix",
	1: "Objects prefixed with 1-octet index",
	2: "Objects prefixed with 2-octet index",
	3: "Objects prefixed with 4-octet index",
	4: "Objects prefixed with 1-octet object size",
	5: "Objects prefixed with 2-octet object size",
	6: "Objects prefixed with 4-octet object size",
	7: "Reserved",
}

/***************************************************************************/
/* Application Layer Object Prefix codes bits */
/***************************************************************************/
var ObjRangeSpecifierCodes = map[byte]string{
	0:  "8-bit Start and Stop Indices in Range Field",
	1:  "16-bit Start and Stop Indices in Range Field",
	2:  "32-bit Start and Stop Indices in Range Field",
	3:  "8-bit Absolute Address in Range Field",
	4:  "16-bit Absolute Address in Range Field",
	5:  "32-bit Absolute Address in Range Field",
	6:  "Length of Range field is 0 (no range field)",
	7:  "8-bit Single Field Quantity",
	8:  "16-bit Single Field Quantity",
	9:  "32-bit Single Field Quantity",
	10: "Reserved",
	11: "Free-format Qualifier, range field has 1 octet count of objects",
	12: "Reserved",
	13: "Reserved",
	14: "Reserved",
	15: "Reserved",
}

var (
	errDNP3PacketTooShort = errors.New("DNS packet too short")
)

type DNP3 struct {
	BaseLayer            // Stores the packet bytes and payload bytes.
	DNP3DataLinkLayer    DNP3DataLinkLayer
	DNP3TransportLayer   DNP3TransportLayer
	DNP3ApplicationLayer DNP3ApplicationLayer
	SomeByte             byte
	AnotherByte          byte
	restOfData           []byte
}

type DNP3DataLinkLayer struct {
	Start   string
	Length  int
	Control struct {
		ControlByte string
		IsMaster    int    `json:"Is Master"`
		PRM         int    `json:"Primary"`
		FCB         int    `json:"Frame Count Bit"`
		FCV         int    `json:"Frame Count Valid"`
		FUNC        string `json:"Function Code"`
	}
	Destination int
	Source      int
	CRC         string
}

type DNP3TransportLayer struct {
	TransportByte string
	Final         int
	First         int
	Sequence      int
}

type DNP3ApplicationLayer struct {
	Control struct {
		ControlByte string
		First       int
		Final       int
		Confirm     int
		Unsolicited int
		Sequence    int
	}
	Function string `json:"Function Code"`
	IINCode  string `json:"Internal Indication (IIN)"`
}

type DNP3AppObject struct {
	Group      int
	Variation  int
	Qualifier  int
	RangeStart int
	RangeStop  int
	DataType   int
	Length     int
}

func (d *DNP3) LayerType() gopacket.LayerType { return LayerTypeDNP3 }

func (d *DNP3) LayerContents() []byte {
	return []byte{d.SomeByte, d.AnotherByte}
}

func (d *DNP3) LayerPayload() []byte {
	return d.restOfData
}

func (d *DNP3) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	// If the data block is too short to be a DNP3 layer, then return an error.
	if len(data) < 10 {
		df.SetTruncated()
		return errDNP3PacketTooShort
	}

	d.linkLayer(data)
	d.transportLayer(data)
	d.applicationLayer(data)

	return nil
}

func decodeDNP3(data []byte, p gopacket.PacketBuilder) error {

	// Attempt to decode the byte slice.
	d := &DNP3{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	// If the decoding worked, add the layer to the packet and set it
	// as the application layer too, if there isn't already one.
	p.AddLayer(d)
	p.SetApplicationLayer(d)

	d.BaseLayer = BaseLayer{Contents: data[:len(data)]}
	d.BaseLayer.Payload = nil

	return p.NextDecoder(gopacket.LayerTypePayload)
}

// CanDecode implements gopacket.DecodingLayer.
func (d *DNP3) CanDecode() gopacket.LayerClass {
	return LayerTypeDNP3
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (d *DNP3) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload returns nil, since TLS encrypted payload is inside TLSAppDataRecord
func (d *DNP3) Payload() []byte {
	return nil
}

func appObject(bytesRead []byte) {

	object := bytesRead[22:]

	// indexSize := uint(object[2] & 0x70 >> 4)
	// QualifierCode := uint(object[2] & 0x0F)
	// fmt.Println(indexSize)
	// fmt.Println(QualifierCode)

	group := int(object[0])
	variation := int(object[1])
	qualifier := int(object[2])
	rangeStart := int(object[3])
	rangeStop := int(object[4])
	dataType := int(object[5])
	length := int(object[6])

	appObject := DNP3AppObject{
		Group:      group,
		Variation:  variation,
		Qualifier:  qualifier,
		RangeStart: rangeStart,
		RangeStop:  rangeStop,
		DataType:   dataType,
		Length:     length,
	}

	out, err := json.Marshal(appObject)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))

}

func (d *DNP3) linkLayer(data []byte) {

	start := d.hexConvert(data[0:2])
	d.DNP3DataLinkLayer.Start = start

	length := int(data[2])
	d.DNP3DataLinkLayer.Length = length

	ctlControl := d.hexConvert([]byte{data[3]})
	d.DNP3DataLinkLayer.Control.ControlByte = ctlControl

	IsMaster := int((data[3] & 0x80) >> 7)
	d.DNP3DataLinkLayer.Control.IsMaster = IsMaster

	PRM := int((data[3] & 0x40) >> 6)
	d.DNP3DataLinkLayer.Control.PRM = PRM

	FCB := int((data[3] & 0x20) >> 5)
	d.DNP3DataLinkLayer.Control.FCB = FCB

	FCV := int((data[3] & 0x10) >> 4)
	d.DNP3DataLinkLayer.Control.FCV = FCV

	FUNCCODE := data[3] & 0x0F
	ctlFUNCCODE := fmt.Sprintf("%d", FUNCCODE)

	var ctlFUNC string
	if PRM == 0x00 {
		ctlFUNC = SfCodes[FUNCCODE]
	}

	if PRM == 0x01 {
		ctlFUNC = PfCodes[FUNCCODE]
	}

	ctlFUNC = ctlFUNC + " (" + ctlFUNCCODE + ")"
	d.DNP3DataLinkLayer.Control.FUNC = ctlFUNC

	// TODO: make sure 0 to 65535
	destination := fmt.Sprintf("%x%x", data[5], data[4])
	destinationInt, _ := strconv.Atoi(destination)
	d.DNP3DataLinkLayer.Destination = destinationInt

	// TODO: make sure 0 to 65535
	source := fmt.Sprintf("%x%x", data[7], data[6])
	sourceInt, _ := strconv.Atoi(source)
	d.DNP3DataLinkLayer.Source = sourceInt

	// TODO: Is correct? Hesapla
	crc := fmt.Sprintf("0x%x%x", data[9], data[8])
	d.DNP3DataLinkLayer.CRC = crc

}

func (d *DNP3) transportLayer(data []byte) {

	transport := fmt.Sprintf("0x%x", data[10])
	d.DNP3TransportLayer.TransportByte = transport

	final := data[10] & 0x80 >> 7
	d.DNP3TransportLayer.Final = int(final)

	first := data[10] & 0x40 >> 6
	d.DNP3TransportLayer.First = int(first)

	sequence := data[10] & 0x3f // 6bit
	d.DNP3TransportLayer.Sequence = int(sequence)

}

func (d *DNP3) applicationLayer(data []byte) {

	// 	/***************************************************************************/
	// /* Application Layer Bit-Masks */
	// /***************************************************************************/
	// 	#define DNP3_AL_UNS   0x10
	// 	#define DNP3_AL_CON   0x20
	// 	#define DNP3_AL_FIN   0x40
	// 	#define DNP3_AL_FIR   0x80
	// 	#define DNP3_AL_SEQ   0x0f
	// 	#define DNP3_AL_FUNC  0xff

	controlByte := fmt.Sprintf("0x%x", data[11])
	d.DNP3ApplicationLayer.Control.ControlByte = controlByte

	first := data[11] & 0x80 >> 7
	d.DNP3ApplicationLayer.Control.First = int(first)

	final := data[11] & 0x40 >> 6
	d.DNP3ApplicationLayer.Control.Final = int(final)

	confirm := data[11] & 0x20 >> 5
	d.DNP3ApplicationLayer.Control.Confirm = int(confirm)

	unsolicited := data[11] & 0x10 >> 4
	d.DNP3ApplicationLayer.Control.Unsolicited = int(unsolicited)

	sequence := data[11] & 0x0f
	d.DNP3ApplicationLayer.Control.Sequence = int(sequence)

	functionCode := data[12]

	// TODO: refactor this hex convert
	src := []byte{functionCode}
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)

	FUNC := fmt.Sprintf("0x%s", dst)

	function := FCodes[functionCode] + " (" + FUNC + ")"
	d.DNP3ApplicationLayer.Function = function

	objectStart := 13
	if d.DNP3DataLinkLayer.Control.IsMaster == 0 {
		objectStart = 15

		// TODO: refactor this hex convert
		src := []byte{data[13], data[14]}
		dst := make([]byte, hex.EncodedLen(len(src)))
		hex.Encode(dst, src)
		IIN := fmt.Sprintf("0x%s", dst)
		IINCode := IINCodes[IIN] + " (" + IIN + ")"
		d.DNP3ApplicationLayer.IINCode = IINCode
	}

	dataSize := len(data[12:])
	fmt.Printf("DataSize %d\n", dataSize)

	switch functionCode {
	case 0: // Confirm
	case 1: // Read
	case 2: // Write
	case 3: // Select
	case 4: // Operate
	case 5: // Direct Operate
	case 6: // Direct Operate No ACK
	case 7: // Immediate Freeze
	case 8: // Immediate Freeze No ACK
	case 9: // Freeze and Clear
	case 10: // Freeze and Clear No ACK
	case 11: // Freeze With Time
	case 12: // Freeze With Time No ACK
	case 13: // Cold Restart
	case 14: // Warm Restart
	case 15: // Initialize Data
	case 16: // Initialize Application
	case 17: // Start Application
	case 18: // Stop Application
	case 19: // Save Configuration
	case 20: // Enable Spontaneous Msg
	case 21: // Disable Spontaneous Msg
	case 22: // Assign Classes
	case 23: // Delay Measurement
	case 24: // Record Current Time
	case 25: // Open File
	case 26: // Close File
	case 27: // Delete File
	case 28: // Get File Info
	case 29: // Authenticate File
	case 30: // Abort File
	case 31: // Activate Config
	case 32: // Authentication Request
	case 33: // Authentication Error
	case 129: // Response
	case 130: // Unsolicited Response
	case 131: // Authentication Response
	}

	objTypeField := binary.BigEndian.Uint16([]byte{data[objectStart], data[objectStart+1]})
	objectGroup := objTypeField & 0xFF00
	objectVariation := objTypeField & 0x00FF
	object := d.hexConvert([]byte{data[objectStart], data[objectStart+1]})
	objectPrefixCode := data[objectStart+2] & 0x70         // OPC
	objectRangeSpecifierCode := data[objectStart+2] & 0x0F // RSC
	fmt.Println(object)
	fmt.Println(objectGroup)
	fmt.Println(objectVariation)
	fmt.Printf("Prefix Code %d\n", objectPrefixCode)
	fmt.Println(ObjPrefixCodes[objectPrefixCode])
	fmt.Printf("Range Specifier Code %d\n", objectRangeSpecifierCode) // 6 means no range field
	fmt.Println(ObjRangeSpecifierCodes[objectRangeSpecifierCode])
	fmt.Println(d.hexConvert([]byte{data[objectStart+3]}))

	offset := objectStart + 3
	rangebytes := 0
	fmt.Println(offset)
	switch objectRangeSpecifierCode {
	case 0:
		// start := offset
		numItems := int(data[offset+1]) - int(data[offset]) + 1
		rangebytes = 2
		fmt.Println(numItems)
		pointAddress := int(data[offset])
		fmt.Println(pointAddress)

	// 	num_items = ( tvb_get_guint8(tvb, offset+1) - tvb_get_guint8(tvb, offset) + 1);
	//   proto_item_set_generated(range_item);
	//   al_ptaddr = tvb_get_guint8(tvb, offset);
	//   proto_tree_add_item(range_tree, hf_dnp3_al_range_start8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	//   proto_tree_add_item(range_tree, hf_dnp3_al_range_stop8, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
	//   rangebytes = 2;

	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
	case 15:

	}
	/* Move offset past any range field */
	offset += rangebytes
	fmt.Println(offset)

	// RSCArrayFirst := []byte{0, 1, 2, 3, 4, 5}

	// if d.contains(RSCArrayFirst, objectRangeSpecifierCode) {

	// }

	/* Special handling for Octet string objects as the variation is the length of the string */
	// temp = objTypeField & 0xFF00
	// if (temp == AL_OBJ_OCT) || (temp == AL_OBJ_OCT_EVT) {
	// 	al_oct_len = al_obj & 0xFF
	// 	al_obj = temp
	// }

	// objectGroup := data[objectStart] & 0x0f
	// objectGroup := fmt.Sprintf("0x%x%x", data[objectStart], data[objectStart+1])

	// fmt.Println(objectGroup)

	// objectGroup, _ := strconv.Atoi(fmt.Sprintf("%d", data[objectStart]))
	// objectVariation, _ := strconv.Atoi(fmt.Sprintf("%d", data[objectStart+1]))
	// fmt.Println(objectGroup)
	// fmt.Println(objectVariation)

	/* Index Size (3-bits x111xxxx) */
	// /* When Qualifier Code != 11    */
	// #define AL_OBJQL_PREFIX_NI     0x00    /* Objects are Packed with no index */
	// #define AL_OBJQL_PREFIX_1O     0x01    /* Objects are prefixed w/ 1-octet index */
	// #define AL_OBJQL_PREFIX_2O     0x02    /* Objects are prefixed w/ 2-octet index */
	// #define AL_OBJQL_PREFIX_4O     0x03    /* Objects are prefixed w/ 4-octet index */
	// #define AL_OBJQL_PREFIX_1OS    0x04    /* Objects are prefixed w/ 1-octet object size */
	// #define AL_OBJQL_PREFIX_2OS    0x05    /* Objects are prefixed w/ 2-octet object size */
	// #define AL_OBJQL_PREFIX_4OS    0x06    /* Objects are prefixed w/ 4-octet object size */

	// /* When Qualifier Code == 11 */
	// #define AL_OBJQL_IDX11_1OIS    0x01    /* 1 octet identifier size */
	// #define AL_OBJQL_IDX11_2OIS    0x02    /* 2 octet identifier size */
	// #define AL_OBJQL_IDX11_4OIS    0x03    /* 4 octet identifier size */

	// /* Qualifier Code (4-bits) */
	// /* 4-bits ( xxxx1111 ) */
	// #define AL_OBJQL_RANGE_SSI8    0x00    /* 00 8-bit Start and Stop Indices in Range Field */
	// #define AL_OBJQL_RANGE_SSI16   0x01    /* 01 16-bit Start and Stop Indices in Range Field */
	// #define AL_OBJQL_RANGE_SSI32   0x02    /* 02 32-bit Start and Stop Indices in Range Field */
	// #define AL_OBJQL_RANGE_AA8     0x03    /* 03 8-bit Absolute Address in Range Field */
	// #define AL_OBJQL_RANGE_AA16    0x04    /* 04 16-bit Absolute Address in Range Field */
	// #define AL_OBJQL_RANGE_AA32    0x05    /* 05 32-bit Absolute Address in Range Field */
	// #define AL_OBJQL_RANGE_R0      0x06    /* 06 Length of Range field is 0 (no range field) */
	// #define AL_OBJQL_RANGE_SF8     0x07    /* 07 8-bit Single Field Quantity */
	// #define AL_OBJQL_RANGE_SF16    0x08    /* 08 16-bit Single Field Quantity */
	// #define AL_OBJQL_RANGE_SF32    0x09    /* 09 32-bit Single Field Quantity */
	//                            /*  0x0A       10 Reserved  */
	// #define AL_OBJQL_RANGE_FF      0x0B    /* 11 Free-format Qualifier, range field has 1 octet count of objects */
	//                            /*  0x0C       12 Reserved  */
	//                            /*  0x0D       13 Reserved  */
	//                            /*  0x0E       14 Reserved  */
	//                            /*  0x0F       15 Reserved  */

	/***************************************************************************/
	/* Application Layer Data Object Qualifier */
	/***************************************************************************/
	// /* Bit-Masks */
	// #define AL_OBJQ_PREFIX         0x70    /* x111xxxx Masks Prefix from Qualifier */
	// #define AL_OBJQ_RANGE          0x0F    /* xxxx1111 Masks Range from Qualifier */

	// objectQualifier := fmt.Sprintf("0x%d", data[objectStart+2])

	// fmt.Println(objectQualifier)

	// src = []byte{data[objectStart], data[objectStart+1]}
	// dst = make([]byte, hex.EncodedLen(len(src)))
	// hex.Encode(dst, src)
	// prefixCode := fmt.Sprintf("0x%s", dst)
	// fmt.Println(prefixCode)

}

func (d *DNP3) IsDNP3(bytesRead []byte) bool {
	if len(bytesRead) >= MIN_HEADER_LENGTH && binary.BigEndian.Uint16(bytesRead[0:2]) == START_FIELD {
		return true
	}
	return false
}

func (d *DNP3) isMaster(bytesRead []byte) bool {
	intValue := int((bytesRead[3] & 0x80) >> 7)
	var boolValue bool = intValue != 0
	return boolValue
}

func (d *DNP3) hexConvert(byteArray []byte) string {
	return "0x" + hex.EncodeToString(byteArray)
}

func (d *DNP3) isMultiPart(bytesRead []byte) bool {
	var FirstOfMulti01 byte = 0x40
	var NotFirstNotLast00 byte = 0x00
	var FinalFrame10 byte = 0x80
	var OneFrame11 byte = 0xC0

	TpFinFir := bytesRead[10] & 0xC0
	switch TpFinFir {
	case FirstOfMulti01:
		return false
	case NotFirstNotLast00:
		return false
	case FinalFrame10:
		return true
	case OneFrame11:
		return true
	}
	return false
}

// Contains tells whether a contains x.
// func (d *DNP3) contains(a []byte, x int) bool {
// 	for _, n := range a {
// 		if x == n {
// 			return true
// 		}
// 	}
// 	return false
// }
