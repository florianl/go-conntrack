// +build linux,!386

package conntrack

import (
	"encoding/binary"
	"errors"

	"golang.org/x/net/bpf"
)

// Various errors which may occour when processing filters
var (
	ErrFilterLength                  = errors.New("Number of filtering instructions are too high")
	ErrFilterAttributeLength         = errors.New("Incorrect length of filter attribute")
	ErrFilterAttributeMaskLength     = errors.New("Incorrect length of filter mask")
	ErrFilterAttributeNotImplemented = errors.New("Filter attribute not implemented")
)

// various consts from include/uapi/linux/bpf_common.h
const (
	// Instruction classes
	bpfLD   = 0x00 /* copy a value into the accumulator */
	bpfLDX  = 0x01 /* load a value into the	index register */
	bpfALU  = 0x04 /* perform operation between the accumulator and index register or constant, and store the result back in the accumulator */
	bpfJMP  = 0x05 /* jump	instruction */
	bpfRET  = 0x06 /* return instructions terminate the filter program */
	bpfMISC = 0x07 /* register transfer	instruction */
	// ld/ldx fields
	bpfW   = 0x00 /* 32-bit word size */
	bpfH   = 0x08 /* 16-bit word size */
	bpfB   = 0x10 /*  8-bit word size */
	bpfIMM = 0x00 /* constant addressing */
	bpfABS = 0x20 /* fixed offset */
	bpfIND = 0x40 /* variable offset */
	// alu/jmp fields
	bpfADD = 0x00
	bpfAND = 0x50
	bpfJA  = 0x00
	bpfJEQ = 0x10
	bpfK   = 0x00

	// include/uapi/linux/filter.h
	bpfTAX = 0x00
	bpfTXA = 0x80

	bpfMAXINSTR = 4096

	bpfVerdictAccept = 0xffffffff
	bpfVerdictReject = 0x00000000
)

type filterCheckStruct struct {
	ct, len int
	mask    bool
	nest    []uint32
}

var filterCheck = map[ConnAttrType]filterCheckStruct{
	AttrOrigIPv4Src:             {ct: ctaIPv4Src, len: 4, mask: true, nest: []uint32{ctaTupleOrig, ctaTupleIP}},
	AttrOrigIPv4Dst:             {ct: ctaIPv4Dst, len: 4, mask: true, nest: []uint32{ctaTupleOrig, ctaTupleIP}},
	AttrOrigIPv6Src:             {ct: ctaUnspec},
	AttrOrigIPv6Dst:             {ct: ctaUnspec},
	AttrOrigPortSrc:             {ct: ctaProtoSrcPort, len: 2, nest: []uint32{ctaTupleOrig, ctaTupleProto}},
	AttrOrigPortDst:             {ct: ctaProtoDstPort, len: 2, nest: []uint32{ctaTupleOrig, ctaTupleProto}},
	AttrReplIPv4Src:             {ct: ctaIPv4Src, len: 4, mask: true, nest: []uint32{ctaTupleReply, ctaTupleIP}},
	AttrReplIPv4Dst:             {ct: ctaIPv4Dst, len: 4, mask: true, nest: []uint32{ctaTupleReply, ctaTupleIP}},
	AttrReplIPv6Src:             {ct: ctaUnspec},
	AttrReplIPv6Dst:             {ct: ctaUnspec},
	AttrReplPortSrc:             {ct: ctaProtoSrcPort, len: 2, nest: []uint32{ctaTupleReply, ctaTupleProto}},
	AttrReplPortDst:             {ct: ctaProtoDstPort, len: 2, nest: []uint32{ctaTupleReply, ctaTupleProto}},
	AttrIcmpType:                {ct: ctaProtoIcmpType, len: 1, nest: []uint32{ctaTupleOrig, ctaTupleProto}},
	AttrIcmpCode:                {ct: ctaProtoIcmpCode, len: 1, nest: []uint32{ctaTupleOrig, ctaTupleProto}},
	AttrIcmpID:                  {ct: ctaProtoIcmpID, len: 2, nest: []uint32{ctaTupleOrig, ctaTupleProto}},
	AttrOrigL3Proto:             {ct: ctaUnspec},
	AttrReplL3Proto:             {ct: ctaUnspec},
	AttrOrigL4Proto:             {ct: ctaProtoNum, len: 1, nest: []uint32{ctaTupleOrig, ctaTupleProto}},
	AttrReplL4Proto:             {ct: ctaProtoNum, len: 1, nest: []uint32{ctaTupleReply, ctaTupleProto}},
	AttrTCPState:                {ct: ctaProtoinfoTCPState, len: 1, nest: []uint32{ctaProtoinfo, ctaProtoinfoTCP}},
	AttrSNatIPv4:                {ct: ctaUnspec},
	AttrDNatIPv4:                {ct: ctaUnspec},
	AttrSNatPort:                {ct: ctaUnspec},
	AttrDNatPort:                {ct: ctaUnspec},
	AttrTimeout:                 {ct: ctaTimeout, len: 4},
	AttrMark:                    {ct: ctaMark, len: 4, mask: true},
	AttrOrigCounterPackets:      {ct: ctaUnspec},
	AttrReplCounterPackets:      {ct: ctaUnspec},
	AttrOrigCounterBytes:        {ct: ctaUnspec},
	AttrReplCounterBytes:        {ct: ctaUnspec},
	AttrUse:                     {ct: ctaUse, len: 4},
	AttrID:                      {ct: ctaID, len: 4},
	AttrStatus:                  {ct: ctaStatus, len: 4},
	AttrTCPFlagsOrig:            {ct: ctaProtoinfoTCPFlagsOrig, len: 1, nest: []uint32{ctaProtoinfo, ctaProtoinfoTCP}},
	AttrTCPFlagsRepl:            {ct: ctaProtoinfoTCPFlagsRepl, len: 1, nest: []uint32{ctaProtoinfo, ctaProtoinfoTCP}},
	AttrTCPMaskOrig:             {ct: ctaUnspec},
	AttrTCPMaskRepl:             {ct: ctaUnspec},
	AttrMasterIPv4Src:           {ct: ctaUnspec},
	AttrMasterIPv4Dst:           {ct: ctaUnspec},
	AttrMasterIPv6Src:           {ct: ctaUnspec},
	AttrMasterIPv6Dst:           {ct: ctaUnspec},
	AttrMasterPortSrc:           {ct: ctaUnspec},
	AttrMasterPortDst:           {ct: ctaUnspec},
	AttrMasterL3Proto:           {ct: ctaUnspec},
	AttrMasterL4Proto:           {ct: ctaUnspec},
	AttrSecmark:                 {ct: ctaSecmark, len: 4},
	AttrOrigNatSeqCorrectionPos: {ct: ctaUnspec},
	AttrOrigNatSeqOffsetBefore:  {ct: ctaUnspec},
	AttrOrigNatSeqOffsetAfter:   {ct: ctaUnspec},
	AttrReplNatSeqCorrectionPos: {ct: ctaUnspec},
	AttrReplNatSeqOffsetBefore:  {ct: ctaUnspec},
	AttrReplNatSeqOffsetAfter:   {ct: ctaUnspec},
	AttrSctpState:               {ct: ctaProtoinfoSCTPState, len: 1, nest: []uint32{ctaProtoinfo, ctaProtoinfoSCTP}},
	AttrSctpVtagOrig:            {ct: ctaProtoinfoSCTPVTagOriginal, len: 4, nest: []uint32{ctaProtoinfo, ctaProtoinfoSCTP}},
	AttrSctpVtagRepl:            {ct: ctaProtoinfoSCTPVTagReply, len: 4, nest: []uint32{ctaProtoinfo, ctaProtoinfoSCTP}},
	AttrDccpState:               {ct: ctaProtoinfoDCCPState, len: 1, nest: []uint32{ctaProtoinfo, ctaProtoinfoDCCP}},
	AttrDccpRole:                {ct: ctaProtoinfoDCCPRole, len: 1, nest: []uint32{ctaProtoinfo, ctaProtoinfoDCCP}},
	AttrTCPWScaleOrig:           {ct: ctaProtoinfoTCPWScaleOrig, len: 1, nest: []uint32{ctaProtoinfo, ctaProtoinfoTCP}},
	AttrTCPWScaleRepl:           {ct: ctaProtoinfoTCPWScaleRepl, len: 1, nest: []uint32{ctaProtoinfo, ctaProtoinfoTCP}},
	AttrZone:                    {ct: ctaZone, len: 2},
	AttrSecCtx:                  {ct: ctaUnspec},
	AttrTimestampStart:          {ct: ctaUnspec},
	AttrTimestampStop:           {ct: ctaUnspec},
	AttrHelperInfo:              {ct: ctaUnspec},
	AttrConnlabels:              {ct: ctaUnspec},
	AttrConnlabelsMask:          {ct: ctaUnspec},
	AttrOrigzone:                {ct: ctaUnspec},
	AttrReplzone:                {ct: ctaUnspec},
	AttrSNatIPv6:                {ct: ctaUnspec},
	AttrDNatIPv6:                {ct: ctaUnspec},
}

func encodeValue(data []byte) (val uint32) {
	switch len(data) {
	case 1:
		val = uint32(data[0])
	case 2:
		val = binary.BigEndian.Uint32(data)
	case 4:
		val = binary.BigEndian.Uint32(data)
	}
	return
}

func compareValue(filter ConnAttr) []bpf.RawInstruction {
	var raw []bpf.RawInstruction
	var bpfOp uint16

	switch len(filter.Data) {
	case 1:
		bpfOp = bpfB
	case 2:
		bpfOp = bpfH
	case 4:
		bpfOp = bpfW
	}

	tmp := bpf.RawInstruction{Op: bpfLD | bpfIND | bpfOp, K: 4}
	raw = append(raw, tmp)
	if filterCheck[filter.Type].mask {
		mask := encodeValue(filter.Mask)
		tmp = bpf.RawInstruction{Op: bpfALU | bpfAND | bpfK, K: mask}

	}
	val := encodeValue(filter.Data)
	tmp = bpf.RawInstruction{Op: bpfJMP | bpfJEQ | bpfK, K: val, Jt: 1}
	raw = append(raw, tmp)

	return raw
}

func filterAttribute(filter ConnAttr) []bpf.RawInstruction {
	var raw []bpf.RawInstruction
	nested := len(filterCheck[filter.Type].nest)

	// sizeof(nlmsghdr) + sizeof(nfgenmsg) = 14
	tmp := bpf.RawInstruction{Op: bpfLD | bpfIMM, K: 14}
	raw = append(raw, tmp)

	// followInstr represents the number of raw instructions to the reject jump
	// after the nestes ones
	var followInstr uint8 = 8
	if filterCheck[filter.Type].mask {
		followInstr++
	}

	if nested != 0 {
		for i, nest := range filterCheck[filter.Type].nest {
			// find nest attribute
			tmp = bpf.RawInstruction{Op: bpfLDX | bpfIMM, K: uint32(nest)}
			raw = append(raw, tmp)
			tmp = bpf.RawInstruction{Op: bpfLD | bpfB | bpfABS, K: 0xfffff00c}
			raw = append(raw, tmp)

			// jump, if nest not found
			failed := followInstr + uint8((nested-i-1)*4)
			tmp = bpf.RawInstruction{Op: bpfJMP | bpfJEQ | bpfK, K: 0, Jt: failed}
			raw = append(raw, tmp)

			tmp = bpf.RawInstruction{Op: bpfALU | bpfADD | bpfK, K: 4}
			raw = append(raw, tmp)
		}
	}

	// find final attribute
	tmp = bpf.RawInstruction{Op: bpfLDX | bpfIMM, K: uint32(filterCheck[filter.Type].ct)}
	raw = append(raw, tmp)
	tmp = bpf.RawInstruction{Op: bpfLD | bpfB | bpfABS, K: 0xfffff00c}
	raw = append(raw, tmp)

	// attribute not found
	tmp = bpf.RawInstruction{Op: bpfJMP | bpfJEQ | bpfK, K: 0, Jt: 4}
	raw = append(raw, tmp)

	tmp = bpf.RawInstruction{Op: bpfMISC | bpfTAX}
	raw = append(raw, tmp)

	// compare expected and actual value
	tmps := compareValue(filter)
	raw = append(raw, tmps...)

	// reject
	tmp = bpf.RawInstruction{Op: bpfRET | bpfK, K: bpfVerdictReject}
	raw = append(raw, tmp)

	return raw
}

// create filter instructions, to check for the subsystem
func filterSubsys(subsys uint32) []bpf.RawInstruction {
	var raw []bpf.RawInstruction

	// Offset between start nlmshdr to nlmsg_type in byte
	tmp := bpf.RawInstruction{Op: bpfLDX | bpfIMM, K: 4}
	raw = append(raw, tmp)

	// Size of the subsytem id in byte
	tmp = bpf.RawInstruction{Op: bpfLD | bpfB | bpfIND, K: 1}
	raw = append(raw, tmp)

	// A == subsys ? jump + 1 : accept
	tmp = bpf.RawInstruction{Op: bpfJMP | bpfJEQ | bpfK, Jt: 1, K: uint32(subsys)}
	raw = append(raw, tmp)

	// verdict -> accept
	tmp = bpf.RawInstruction{Op: bpfRET | bpfK, K: bpfVerdictAccept}
	raw = append(raw, tmp)

	return raw
}

func constructFilter(subsys CtTable, filters []ConnAttr) ([]bpf.RawInstruction, error) {
	var raw []bpf.RawInstruction

	tmp := filterSubsys(uint32(subsys))
	raw = append(raw, tmp...)

	for _, filter := range filters {
		if _, ok := filterCheck[filter.Type]; !ok {
			return nil, ErrFilterAttributeNotImplemented
		}
		if len(filter.Data) != filterCheck[filter.Type].len {
			return nil, ErrFilterAttributeLength
		}
		if filterCheck[filter.Type].mask && len(filter.Mask) != filterCheck[filter.Type].len {
			return nil, ErrFilterAttributeMaskLength
		}
		tmp = filterAttribute(filter)
		raw = append(raw, tmp...)
	}

	// final verdict -> Accept
	finalVerdict := bpf.RawInstruction{Op: bpfRET | bpfK, K: bpfVerdictAccept}
	raw = append(raw, finalVerdict)

	if len(raw) >= bpfMAXINSTR {
		return nil, ErrFilterLength
	}
	return raw, nil
}

func (nfct *Nfct) attachFilter(subsys CtTable, filters []ConnAttr) error {

	bpfFilters, err := constructFilter(subsys, filters)
	if err != nil {
		return err
	}
	return nfct.con.SetBPF(bpfFilters)
}

func (nfct *Nfct) removeFilter() error {
	return nfct.con.RemoveBPF()
}
