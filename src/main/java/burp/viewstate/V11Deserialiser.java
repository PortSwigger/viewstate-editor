package burp.viewstate;

import burp.IExtensionHelpers;

import java.util.*;

import static burp.viewstate.DeserialisedObject.DeserialisedObjectType.*;
import static burp.viewstate.ViewState.Version.V11;

class V11Deserialiser
{
    private static final Class<?>[] KNOWN_TYPES = new Class[]{Object.class, Hashtable.class, java.awt.Color.class, Short.class, Long.class};

    private final byte[] deserializationData;
    private final IExtensionHelpers helpers;

    private int current;
    private byte[] builder;
    private boolean errorOccurred;

    private List<Object> deserializedTypeTable;
    private HashMap<String, Object> deserializedConverterTable;

    V11Deserialiser(byte[] data, IExtensionHelpers helpers)
    {
        this.deserializationData = data;
        this.helpers = helpers;
    }

    public static boolean canDeserialise(byte[] b)
    {
        return b.length > 1 && b[1] == '<';
    }

    public ViewState deserialise() throws Exception
    {
        if (deserializationData[1] == '<')
        {
            ViewState vs = new ViewState(V11);

            initializeDeserializer();
            vs.value = deserialiseValue();

            // check for MAC
            if (!errorOccurred)
            {
                switch (deserializationData.length - current)
                {
                    case 0:
                        vs.macEnabled = false;
                        break;
                    case 20:
                    case 32:
                        vs.macEnabled = true;
                        break;
                    default:
                        errorOccurred = true;
                        break;
                }
            }

            vs.errorOccurred = errorOccurred;
            vs.raw = deserializationData;

            return vs;
        }

        throw new Exception("Not a valid ASP.NET 1.1 LOS stream");
    }

    private void initializeDeserializer()
    {
        deserializedTypeTable = new ArrayList<>();
        deserializedConverterTable = new HashMap<>();

        builder = new byte[0x100];
    }

    private DeserialisedObject deserialiseValue()
    {
        if (errorOccurred)
        {
            return new DeserialisedObject(ERROR, null);
        }

        try
        {
            String token = consumeOneToken();

            if ((current >= deserializationData.length) || (deserializationData[current] != '<'))
            {
                return new DeserialisedObject(STRING, token);
            }

            current++;
            if (token.length() == 1)
            {
                byte[] buffer;
                char ch = token.charAt(0);
                switch (ch)
                {
                    case 'p':       // pair
                    {
                        DeserialisedObject first;
                        DeserialisedObject second;

                        if (deserializationData[current] != ';')
                        {
                            first = deserialiseValue();
                        }
                        else
                        {
                            first = new DeserialisedObject(NULL, null);
                        }
                        current++;
                        if (deserializationData[current] != '>')
                        {
                            second = deserialiseValue();
                        }
                        else
                        {
                            second = new DeserialisedObject(NULL, null);
                        }

                        current++;
                        return new DeserialisedObject(PAIR, new Pair(first, second));
                    }

                    case 't':       // triplet
                    {
                        DeserialisedObject first;
                        DeserialisedObject second;
                        DeserialisedObject third;

                        if (deserializationData[current] != ';')
                        {
                            first = deserialiseValue();
                        }
                        else
                        {
                            first = new DeserialisedObject(NULL, null);
                        }
                        current++;
                        if (deserializationData[current] != ';')
                        {
                            second = deserialiseValue();
                        }
                        else
                        {
                            second = new DeserialisedObject(NULL, null);
                        }
                        current++;
                        if (deserializationData[current] != '>')
                        {
                            third = deserialiseValue();
                        }
                        else
                        {
                            third = new DeserialisedObject(NULL, null);
                        }

                        current++;
                        return new DeserialisedObject(TRIPLET, new Triplet(first, second, third));
                    }

                    case 'i':       // number
                    {
                        int i = 0;
                        try
                        {
                            i = Integer.parseInt(consumeOneToken());
                        }
                        catch (NumberFormatException ignored)
                        {
                        }
                        current++;
                        return new DeserialisedObject(INT32, i);
                    }

                    case 'o':       // boolean
                    {
                        boolean b = (deserializationData[current] == 't');
                        current += 2;
                        return new DeserialisedObject(BOOLEAN, b);
                    }

                    case 'l':       // list
                    {
                        List<DeserialisedObject> list = new ArrayList<>();

                        while (deserializationData[current] != '>' && !errorOccurred)
                        {
                            if (deserializationData[current] != ';')
                            {
                                list.add(deserialiseValue());
                            }
                            else
                            {
                                list.add(new DeserialisedObject(NULL, null));
                            }
                            current++;
                        }

                        current++;
                        return new DeserialisedObject(LIST, list);
                    }

                    case '@':       // string array
                    {
                        List<DeserialisedObject> list = new ArrayList<>();

                        while (deserializationData[current] != '>' && !errorOccurred)
                        {
                            if (deserializationData[current] != ';')
                            {
                                list.add(new DeserialisedObject(STRING, consumeOneToken()));
                            }
                            list.add(new DeserialisedObject(NULL, null));
                            current++;
                        }

                        current++;
                        DeserialisedObject[] o = new DeserialisedObject[list.size()];
                        list.toArray(o);
                        return new DeserialisedObject(ARRAY, new DeserialisedArray(String.class, o));
                    }

                    case 'h':       // hashtable
                    {
                        List<DeserialisedObject> list = new ArrayList<>();
                        while (deserializationData[current] != '>' && !errorOccurred)
                        {
                            DeserialisedObject name = deserialiseValue();
                            current++;
                            DeserialisedObject value;
                            if (deserializationData[current] != ';')
                            {
                                value = deserialiseValue();
                            }
                            else
                            {
                                value = new DeserialisedObject(NULL, null);
                            }
                            current++;

                            list.add(new DeserialisedObject(HASHTABLE_PAIR, new DeserialisedObject[]{name, value}));
                        }
                        current++;
                        DeserialisedObject[] o = new DeserialisedObject[list.size()];
                        list.toArray(o);
                        return new DeserialisedObject(HASHTABLE, o);
                    }

                    case 'b':       // serialised object
                    {
                        buffer = helpers.base64Decode(consumeOneToken());
                        current++;
                        return new DeserialisedObject(SERIALISED_OBJECT, new SerialisedObject(helpers.bytesToString(buffer)));
                    }
                }

                DeserialisedObject o = consumeTypeConverterValue(token);
                current++;
                return o;
            }
            else if (token.charAt(0) == '@')
            {
                Object type = typeFromTypeRef(token.substring(1));
                DeserialisedObject o = consumeArray(type);
                current++;
                return o;
            }
            else
            {
                DeserialisedObject o = consumeTypeConverterValue(token);
                current++;
                return o;
            }
        }
        catch (Exception e)
        {
            errorOccurred = true;
            return new DeserialisedObject(ERROR, null);
        }
    }

    private String consumeOneToken()
    {
        int length = 0;
        while (current < deserializationData.length)
        {
            switch (deserializationData[current])
            {
                case ';':
                case '<':
                case '>':
                    return helpers.bytesToString(Arrays.copyOfRange(builder, 0, length));

                case '\\':
                    current++;
                    if (deserializationData[current] == 'e')
                    {
                        current++;
                        return "";
                    }
                    builder[length] = deserializationData[current];
                    length++;
                    break;

                default:
                    builder[length] = deserializationData[current];
                    length++;
                    break;
            }

            current++;

            if (length >= builder.length)
            {
                byte[] destinationArray = new byte[builder.length * 2];
                System.arraycopy(builder, 0, destinationArray, 0, builder.length);
                builder = destinationArray;
            }
        }

        return helpers.bytesToString(Arrays.copyOfRange(builder, 0, length));
    }

    private Object typeFromTypeRef(String typeRef)
    {
        int number = parseNumericString(typeRef);

        Object type = typeFromTypeCode(number);

        if (type == null)
        {
            type = new Type(typeRef);
            deserializedTypeTable.add(type);
        }

        return type;
    }

    private int parseNumericString(String num)
    {
        int num2 = 0;
        int length = num.length();

        for (int i = 0; i < length; i++)
        {
            switch (num.charAt(i))
            {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    num2 *= 10;
                    num2 += num.charAt(i) - '0';
                    break;

                default:
                    num2 = -1;
                    i = length;
                    break;
            }
        }

        return num2;
    }

    private Object typeFromTypeCode(int number)
    {
        if (number == -1)
        {
            return null;
        }

        if (number <= 0x31)
        {
            return KNOWN_TYPES[number];
        }

        return deserializedTypeTable.get(number - 50);
    }


    private DeserialisedObject consumeArray(Object type)
    {
        List<DeserialisedObject> list = new ArrayList<>();

        while (deserializationData[current] != '>' && !errorOccurred)
        {
            if (deserializationData[current] != ';')
            {
                list.add(deserialiseValue());
            }
            else
            {
                list.add(new DeserialisedObject(NULL, null));
            }

            current++;
        }

        DeserialisedObject[] array = new DeserialisedObject[list.size()];
        list.toArray(array);

        return new DeserialisedObject(ARRAY, new DeserialisedArray(type, array));
    }

    private DeserialisedObject consumeTypeConverterValue(String token)
    {
        Object type;
        int number = parseNumericString(token);

        if (number != -1)
        {
            deserializedConverterTable.computeIfAbsent(token, k -> typeFromTypeCode(number));
        }
        else
        {
            type = new Type(token);
            deserializedTypeTable.add(type);
            int num2 = deserializedTypeTable.size() + 50;
            deserializedConverterTable.put(Integer.toString(num2), type);
            deserializedTypeTable.add(type);
        }

        String text = consumeOneToken();

        return new DeserialisedObject(SERIALISED_OBJECT, new SerialisedObject(text));
    }
}
