package app;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal JSON support for flat objects (the only shape this API ever sends
 * or receives). Hand-rolled rather than pulling in a JSON library, matching
 * the rest of the codebase's zero-runtime-dependency approach.
 */
public final class JsonUtil {

    private JsonUtil() {
    }

    public static final class JsonException extends RuntimeException {
        public JsonException(String message) {
            super(message);
        }
    }

    /** Parses a flat JSON object into a Map. Non-string values are kept as their raw literal text. */
    public static Map<String, String> parseFlatObject(String text) {
        if (text == null) {
            throw new JsonException("empty body");
        }
        Parser p = new Parser(text);
        p.skipWhitespace();
        p.expect('{');
        Map<String, String> result = new LinkedHashMap<>();
        p.skipWhitespace();
        if (p.peek() == '}') {
            p.next();
            return result;
        }
        while (true) {
            p.skipWhitespace();
            String key = p.parseString();
            p.skipWhitespace();
            p.expect(':');
            p.skipWhitespace();
            String value = p.parseValueAsString();
            result.put(key, value);
            p.skipWhitespace();
            char c = p.next();
            if (c == ',') {
                continue;
            }
            if (c == '}') {
                break;
            }
            throw new JsonException("expected ',' or '}'");
        }
        return result;
    }

    /** Same as {@link #parseFlatObject}, but returns an empty map instead of throwing on malformed input. */
    public static Map<String, String> parseFlatObjectSilently(String text) {
        try {
            return parseFlatObject(text);
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    public static String writeObject(Map<String, ?> fields) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, ?> e : fields.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escape(e.getKey())).append("\":");
            Object v = e.getValue();
            if (v == null) {
                sb.append("null");
            } else if (v instanceof Number || v instanceof Boolean) {
                sb.append(v.toString());
            } else {
                sb.append('"').append(escape(v.toString())).append('"');
            }
        }
        sb.append('}');
        return sb.toString();
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    private static final class Parser {
        private final String s;
        private int i = 0;

        Parser(String s) {
            this.s = s;
        }

        void skipWhitespace() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        char peek() {
            if (i >= s.length()) {
                throw new JsonException("unexpected end of input");
            }
            return s.charAt(i);
        }

        char next() {
            if (i >= s.length()) {
                throw new JsonException("unexpected end of input");
            }
            return s.charAt(i++);
        }

        void expect(char c) {
            char got = next();
            if (got != c) {
                throw new JsonException("expected '" + c + "' but got '" + got + "'");
            }
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char esc = next();
                    switch (esc) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (i + 4 > s.length()) {
                                throw new JsonException("bad unicode escape");
                            }
                            String hex = s.substring(i, i + 4);
                            i += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                        }
                        default -> throw new JsonException("bad escape: \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        String parseValueAsString() {
            skipWhitespace();
            if (peek() == '"') {
                return parseString();
            }
            int start = i;
            while (i < s.length() && ",}]".indexOf(s.charAt(i)) < 0 && !Character.isWhitespace(s.charAt(i))) {
                i++;
            }
            if (i == start) {
                throw new JsonException("expected value");
            }
            return s.substring(start, i).trim();
        }
    }
}
