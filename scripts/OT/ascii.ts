/*
 *  ASCII helpers for showing text based oblivious transfer

const to_array = function (ascii) {
  var array = Array(ascii.length);
  for (var i = 0; i < ascii.length; i++) {
    array[i] = ascii[i].charCodeAt();
  }
  return array;
};
const to_ascii = function (array: Buffer) {
  return String.fromCharCode.apply(null, array);
};

module.exports = {
  to_array: to_array,
  to_ascii: to_ascii
};
 */

const to_array = (ascii: string): number[] => {
  const array: number[] = Array(ascii.length);
  for (let i = 0; i < ascii.length; i++) {
    array[i] = ascii.charCodeAt(i);
  }
  return array;
};

const to_ascii = (array: Uint8Array): string => {
  return String.fromCharCode(...array);
};

// Exporting the functions using modern ES module syntax
export { to_array, to_ascii };
