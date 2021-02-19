package burp.viewstate;

class Unit
{
    private static final String[] TYPES = new String[]{"[empty]", "pixels", "points", "picas", "inches", "mm", "cm", "%", "em", "ex"};

    private final double value;
    private final byte type;
    
    Unit(double value, byte type)
    {
        this.value = value;
        this.type = type;
    }
    
    @Override
    public String toString()
    {
        if (type == 0)
        {
            return TYPES[0];
        }
        
        return value + " " + TYPES[type];
    }
}
