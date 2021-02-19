package burp.viewstate;

public class Pair
{
    public DeserialisedObject first;
    public DeserialisedObject second;

    public Pair(DeserialisedObject x, DeserialisedObject y)
    {
        first = x;
        second = y;
    }    
    
    @Override
    public String toString()
    {
        return "pair:[" + first.toString() + "," + second.toString() + "]";
    }
}
