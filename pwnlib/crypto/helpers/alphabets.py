# based on code from: https://raw.githubusercontent.com/tigertv/secretpy/master/secretpy/alphabets.py

def get_index_in_alphabet(char, alphabet):
    for j in range(len(alphabet)):
        try:
            alphabet[j].index(char)
            break
        except ValueError:
            pass
    return j


BINARY = u"01"
DECIMAL = u"0123456789"
DOZENAL = u"0123456789ab"
HEX = u"0123456789abcdef"
OCTAL = u"01234567"

ARABIC = u"غظضذخثتشرقصفعسنملكيطحزوهدجبأ"
DANISH = u"abcdefghijklmnopqrstuvwxyzæøå"
DUTCH = u"abcdefghijklmnopqrstuvwxyz"
ENGLISH = u"abcdefghijklmnopqrstuvwxyz"
GERMAN = u"abcdefghijklmnopqrstuvwxyzäöüß"
GREEK = u"αβγδεζηθικλμνξοπρστυφχψω"
HEBREW = u"אבגדהוזחטיךכלםמןנסעףפץצקרשת"
ICELANDIC = u"aábdðeéfghiíjklmnoóprstuúvxyýþæö"
ITALIAN = u"abcdefghilmnopqrstuvz"
NORWEGIAN = DANISH
POLISH = u"aąbcćdeęfghijklłmnńoóprsśtuwyzźż"
RUSSIAN = u"абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
SPANISH = u"abcdefghijklmnñopqrstuvwxyz"
TURKISH = u"abcçdefgğhıijklmnoöprsştuüvyz"

ENGLISH_SQUARE_IJ = (
    u"a", u"b", u"c", u"d", u"e",
    u"f", u"g", u"h", u"ij", u"k",
    u"l", u"m", u"n", u"o", u"p",
    u"q", u"r", u"s", u"t", u"u",
    u"v", u"w", u"x", u"y", u"z",
)

ENGLISH_SQUARE_OQ = (
    u"a", u"b", u"c", u"d", u"e",
    u"f", u"g", u"h", u"i", u"j",
    u"k", u"l", u"m", u"n", u"oq",
    u"p", u"r", u"s", u"t", u"u",
    u"v", u"w", u"x", u"y", u"z",
)

ENGLISH_SQUARE_NO_Z = (
    u"a", u"b", u"c", u"d", u"e",
    u"f", u"g", u"h", u"i", u"j",
    u"k", u"l", u"m", u"n", u"o",
    u"p", u"q", u"r", u"s", u"t",
    u"u", u"v", u"w", u"x", u"y",
)

GERMAN_SQUARE = (
    u"aä", u"b", u"c", u"d", u"e",
    u"f", u"g", u"h", u"ij", u"k",
    u"l", u"m", u"n", u"oö", u"p",
    u"q", u"r", u"sß", u"t", u"uü",
    u"v", u"w", u"x", u"y", u"z"
)

SPANISH_SQUARE = (
    u"a", u"b", u"c", u"d", u"e",
    u"f", u"g", u"h", u"ij", u"k",
    u"l", u"m", u"nñ", u"o", u"p",
    u"q", u"r", u"s", u"t", u"u",
    u"v", u"w", u"x", u"y", u"z"
)

RUSSIAN_SQUARE = (
    u"а", u"б", u"в", u"г", u"д", u"её",
    u"ж", u"з", u"ий", u"к", u"л", u"м",
    u"н", u"о", u"п", u"р", u"с", u"т",
    u"у", u"ф", u"х", u"ц", u"ч", u"ш",
    u"щ", u"ы", u"ьъ", u"э", u"ю", u"я",
    u"0", u"1", u"2", u"3", u"4", u"5"
)

JAPANESE_HIRAGANA = (
    u"あいうえお"
    u"かきくけこ"
    u"がぎぐげご"
    u"さしすせそ"
    u"ざじずぜぞ"
    u"たちつてと"
    u"だぢづでど"
    u"なにぬねの"
    u"はひふへほ"
    u"ばびぶべぼ"
    u"ぱぴぷぺぽ"
    u"まみむめも"
    u"やゆよ"
    u"らりるれろ"
    u"わを"
    u"ん"
    u"ゃゅょぁぇ"
    u"じづ"
)
