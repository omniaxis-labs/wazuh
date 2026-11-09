// Removed from stored text: C0/C1 controls (except newline), every format
// character (zero-width, bidi, soft hyphen, invisible operators, tags) and
// every default-ignorable code point, plus visible-blank fillers that are not
// formally ignorable. Ordinary combining marks are kept so accents survive.
export const STRIP =
	/(?!\n)\p{Cc}|\p{Cf}|\p{Default_Ignorable_Code_Point}|[\u115F\u1160\u17B4\u17B5\u180E\u2800\u3164]|\u034F|[\uFE00-\uFE0F]/gu;

/** NFKC-normalise and remove control, invisible and bidi characters. */
export function cleanText(s: string): string {
	return s.replace(STRIP, "").normalize("NFKC").replace(STRIP, "");
}
