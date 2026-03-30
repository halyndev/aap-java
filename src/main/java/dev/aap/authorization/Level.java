package dev.aap.authorization;
public enum Level {
    OBSERVE(0,"observe"), SUGGEST(1,"suggest"), ASSISTED(2,"assisted"),
    SUPERVISED(3,"supervised"), AUTONOMOUS(4,"autonomous");
    public final int value; public final String label;
    Level(int v, String l) { value=v; label=l; }
}
