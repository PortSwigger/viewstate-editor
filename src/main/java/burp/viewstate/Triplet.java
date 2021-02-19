package burp.viewstate;

public class Triplet
{
    public DeserialisedObject first;
    public DeserialisedObject second;
    public DeserialisedObject third;
    
    public Triplet(DeserialisedObject x, DeserialisedObject y, DeserialisedObject z)
    {
        first = x;
        second = y;
        third = z;
    }
    
    @Override
    public String toString()
    {
        return "triplet:[" + first.toString() + "," + second.toString() + "," + third.toString() + "]";
    }
}
