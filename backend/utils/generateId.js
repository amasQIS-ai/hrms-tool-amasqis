export function generateId(str) {
  const number = Math.floor(1000 + Math.random() * 9000); // Generates a random 4-digit number
  return str + number.toString(); // Concatenates the input string with the 4-digit number
}
