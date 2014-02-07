//
// asn1hex.js - Hexadecimal represented ASN.1 string library
//
//
// version: 1.0 (2010-Jun-03)
//
// Copyright (c) 2010 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://www.opensource.org/licenses/mit-license.php
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.
// 
//
// Depends on:
//

// MEMO:
//   f('3082025b02...', 2) ... 82025b ... 3bytes
//   f('020100', 2) ... 01 ... 1byte
//   f('0203001...', 2) ... 03 ... 1byte
//   f('02818003...', 2) ... 8180 ... 2bytes
//   f('3080....0000', 2) ... 80 ... -1
//
//   Requirements:
//   - ASN.1 type octet length MUST be 1. 
//     (i.e. ASN.1 primitives like SET, SEQUENCE, INTEGER, OCTETSTRING ...)
//   - 

asn1hex = {};

asn1hex.getByteLengthOfL_AtObj = function(s, pos) {
  if (s.substring(pos + 2, pos + 3) != '8') return 1;
  var i = parseInt(s.substring(pos + 3, pos + 4));
  if (i == 0) return -1; 		// length octet '80' indefinite length
  if (0 < i && i < 10) return i + 1;	// including '8?' octet;
  return -2;				// malformed format
}

asn1hex.getHexOfL_AtObj = function(s, pos) {
  var len = asn1hex.getByteLengthOfL_AtObj(s, pos);
  if (len < 1) return '';
  return s.substring(pos + 2, pos + 2 + len * 2);
}

//
//   getting ASN.1 length value at the position 'idx' of
//   hexa decimal string 's'.
//
//   f('3082025b02...', 0) ... 82025b ... ???
//   f('020100', 0) ... 01 ... 1
//   f('0203001...', 0) ... 03 ... 3
//   f('02818003...', 0) ... 8180 ... 128
asn1hex.getIntOfL_AtObj = function(s, pos) {
  var hLength = asn1hex.getHexOfL_AtObj(s, pos);
  if (hLength == '') return -1;
  var bi;
  if (parseInt(hLength.substring(0, 1)) < 8) {
     bi = parseBigInt(hLength, 16);
  } else {
     bi = parseBigInt(hLength.substring(2), 16);
  }
  return bi.intValue();
}

//
// get ASN.1 value starting string position 
// for ASN.1 object refered by index 'idx'.
//
asn1hex.getStartPosOfV_AtObj = function(s, pos) {
  var l_len = asn1hex.getByteLengthOfL_AtObj(s, pos);
  if (l_len < 0) return l_len;
  return pos + (l_len + 1) * 2;
}

asn1hex.getHexOfV_AtObj = function(s, pos) {
  var pos1 = asn1hex.getStartPosOfV_AtObj(s, pos);
  var len = asn1hex.getIntOfL_AtObj(s, pos);
  return s.substring(pos1, pos1 + len * 2);
}

asn1hex.getPosOfNextSibling_AtObj = function(s, pos) {
  var pos1 = asn1hex.getStartPosOfV_AtObj(s, pos);
  var len = asn1hex.getIntOfL_AtObj(s, pos);
  return pos1 + len * 2;
}

asn1hex.getPosArrayOfChildren_AtObj = function(h, pos) {
  var a = new Array();
  var p0 = asn1hex.getStartPosOfV_AtObj(h, pos);
  a.push(p0);

  var len = asn1hex.getIntOfL_AtObj(h, pos);
  var p = p0;
  var k = 0;
  while (1) {
    var pNext = asn1hex.getPosOfNextSibling_AtObj(h, p);
    if (pNext == null || (pNext - p0  >= (len * 2))) break;
    if (k >= 200) break;

    a.push(pNext);
    p = pNext;

    k++;
  }

  return a;
}

if (typeof module !== "undefined")
	module.exports = asn1hex;
else
	exports = asn1hex;

