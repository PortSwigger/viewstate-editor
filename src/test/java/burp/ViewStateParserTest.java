package burp;

import burp.viewstate.ViewState.Version;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;

import java.net.URLDecoder;
import java.util.Base64;
import java.util.stream.Stream;

import static burp.IRequestInfo.CONTENT_TYPE_URL_ENCODED;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;

class ViewStateParserTest
{
    private static final byte[] RESPONSE_NON_HTML = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nfoo".getBytes(UTF_8);
    private static final byte[] RESPONSE_NO_VIEWSTATE = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: 84\r\n\r\n<html><body><form><input type=\"hidden\" name=\"foo\" value=\"bar\"/></form></body></html>".getBytes(UTF_8);

    // View state 1.1 used here is from http://aspalliance.com/articleViewer.aspx?aId=135&pId=
    private static final String VIEWSTATE_1_1_URL_ENCODED = "dDwxMjM0NTY3ODkwO3Q8cDxsPHBycEE7cHJwQjtwcnBDOz47bDx2YWxBO3ZhbEI7dmFsQzs%2BPjtsPGk8MD47aTwyPjtpPDM%2BO2k8NT47PjtsPHQ8cDxsPHBycEE7cHJwQjs%2BO2w8dmFsQTt2YWxCOz4%2BOzs%2BO3Q8cDxsPHBycEE7cHJwQjs%2BO2w8dmFsQTt2YWxCOz4%2BOzs%2BO3Q8cDxsPHBycEE7cHJwQjs%2BO2w8dmFsQTt2YWxCOz4%2BOzs%2BO3Q8cDxsPHBycEE7cHJwQjs%2BO2w8dmFsQTt2YWxCOz4%2BOzs%2BOz4%2BOz4%3D";
    private static final String VIEWSTATE_1_1 = "dDwxMjM0NTY3ODkwO3Q8cDxsPHBycEE7cHJwQjtwcnBDOz47bDx2YWxBO3ZhbEI7dmFsQzs+PjtsPGk8MD47aTwyPjtpPDM+O2k8NT47PjtsPHQ8cDxsPHBycEE7cHJwQjs+O2w8dmFsQTt2YWxCOz4+Ozs+O3Q8cDxsPHBycEE7cHJwQjs+O2w8dmFsQTt2YWxCOz4+Ozs+O3Q8cDxsPHBycEE7cHJwQjs+O2w8dmFsQTt2YWxCOz4+Ozs+O3Q8cDxsPHBycEE7cHJwQjs+O2w8dmFsQTt2YWxCOz4+Ozs+Oz4+Oz4=";
    private static final String DESERIALISED_VIEW_STATE_1_1_VALUE = "triplet:[1234567890,triplet:[pair:[[prpA, prpB, prpC],[valA, valB, valC]],[0, 2, 3, 5],[triplet:[pair:[[prpA, prpB],[valA, valB]],null,null], triplet:[pair:[[prpA, prpB],[valA, valB]],null,null], triplet:[pair:[[prpA, prpB],[valA, valB]],null,null], triplet:[pair:[[prpA, prpB],[valA, valB]],null,null]]],null]";

    private static final String VIEWSTATE_2_0_URL_ENCODED = "%2FwEPDwUIOTEyNDUzNDYPZBYCAgMPZBYCAgEPFgIeBFRleHQFDUhlbGxvLCBXb3JsZCFkZI0xW5cmFDUa3BSEmV3SdU9raKTO";
    private static final String VIEWSTATE_2_0 = "/wEPDwUIOTEyNDUzNDYPZBYCAgMPZBYCAgEPFgIeBFRleHQFDUhlbGxvLCBXb3JsZCFkZI0xW5cmFDUa3BSEmV3SdU9raKTO";
    private static final String DESERIALISED_VIEW_STATE_2_0_VALUE = "pair:[pair:[91245346,pair:[null,[3, pair:[null,[1, pair:[[Text, Hello, World!],null]]]]]],null]";

    @Mock
    private IRequestInfo requestInfo;

    @Mock
    private IResponseInfo responseInfo;

    @Mock
    private IExtensionHelpers helpers;

    @BeforeEach
    void setUp()
    {
        openMocks(this);

        when(helpers.stringToBytes(anyString())).thenAnswer(i -> i.getArgument(0, String.class).getBytes(UTF_8));
        when(helpers.bytesToString(any(byte[].class))).thenAnswer(i -> new String(i.getArgument(0, byte[].class), UTF_8));

        when(helpers.urlDecode(anyString())).thenAnswer(i -> URLDecoder.decode(i.getArgument(0, String.class), UTF_8.name()));
        when(helpers.urlDecode(any(byte[].class))).thenAnswer(i -> URLDecoder.decode(new String(i.getArgument(0, byte[].class), UTF_8), UTF_8.name()).getBytes(UTF_8));

        when(helpers.base64Decode(any(byte[].class))).thenAnswer(i -> Base64.getDecoder().decode(i.getArgument(0, byte[].class)));

        when(helpers.indexOf(any(byte[].class), any(byte[].class), anyBoolean(), anyInt(), anyInt())).thenAnswer(i ->
                {
                    int index = new String(i.getArgument(0, byte[].class), UTF_8)
                                    .substring(i.getArgument(3, Integer.class), i.getArgument(4, Integer.class))
                                    .indexOf(new String(i.getArgument(1, byte[].class), UTF_8));

                    if (index == -1)
                    {
                        return -1;
                    }

                    return index + i.getArgument(3, Integer.class);
                }
        );
    }

    @Test
    void givenNoViewStateParameter_whenParseRequest_thenNullReturned()
    {
        when(requestInfo.getParameters()).thenReturn(emptyList());
        when(helpers.analyzeRequest(any(byte[].class))).thenReturn(requestInfo);

        ViewStateInfo viewStateInfo = new ViewStateParser(helpers).parseRequest(requestInfo);

        assertThat(viewStateInfo).isNull();
    }

    @Test
    void givenNonHtmlResponse_whenParseResponse_thenNullReturned()
    {
        when(responseInfo.getInferredMimeType()).thenReturn("text");
        when(helpers.analyzeResponse(any(byte[].class))).thenReturn(responseInfo);

        ViewStateInfo viewStateInfo = new ViewStateParser(helpers).parseResponse(responseInfo, RESPONSE_NON_HTML);

        assertThat(viewStateInfo).isNull();
    }

    @Test
    void givenHtmlResponse_withNoViewStateField_whenParseResponse_thenNullReturned()
    {
        when(responseInfo.getInferredMimeType()).thenReturn("HTML");
        when(helpers.analyzeResponse(any(byte[].class))).thenReturn(responseInfo);

        ViewStateInfo viewStateInfo = new ViewStateParser(helpers).parseResponse(responseInfo, RESPONSE_NO_VIEWSTATE);

        assertThat(viewStateInfo).isNull();
    }

    @ParameterizedTest
    @MethodSource("viewStateUrlEncodedTestArgsProvider")
    void givenUrlEncodedViewStateParameter_whenParseRequest_thenViewStateIsCorrectlyDeserialised(String viewStateUrlEncoded, Version version, boolean macEnabled, String deserialisedViewStateValue)
    {
        ViewStateParam viewStateParam = new ViewStateParam(viewStateUrlEncoded);
        when(requestInfo.getContentType()).thenReturn(CONTENT_TYPE_URL_ENCODED);
        when(requestInfo.getParameters()).thenReturn(singletonList(viewStateParam));
        when(helpers.analyzeRequest(any(byte[].class))).thenReturn(requestInfo);

        ViewStateInfo viewStateInfo = new ViewStateParser(helpers).parseRequest(requestInfo);

        assertThat(viewStateInfo.from).isEqualTo(viewStateParam.getValueStart());
        assertThat(viewStateInfo.to).isEqualTo(viewStateParam.getValueEnd());

        assertThat(viewStateInfo.viewState).isNotNull();
        assertThat(viewStateInfo.viewState.errorOccurred).isFalse();
        assertThat(viewStateInfo.viewState.macEnabled).isEqualTo(macEnabled);
        assertThat(viewStateInfo.viewState.version).isEqualTo(version);
        assertThat(viewStateInfo.viewState.value.toString()).isEqualTo(deserialisedViewStateValue);
    }

    @ParameterizedTest
    @MethodSource("viewStateInResponseBodyTestArgsProvider")
    void givenHtmlResponse_withViewStateField_whenParseResponse_thenViewStateReturned(String viewState, Version version, boolean macEnabled, String deserialisedViewStateValue)
    {
        when(responseInfo.getInferredMimeType()).thenReturn("HTML");
        when(helpers.analyzeResponse(any(byte[].class))).thenReturn(responseInfo);

        String htmlBodyWithViewStateField = format("<html><body><form><input type=\"hidden\" name=\"__VIEWSTATE\" value=\"%s\"/></form></body></html>", viewState);
        String responseWithViewStateStr = format("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", htmlBodyWithViewStateField.length(), htmlBodyWithViewStateField);

        ViewStateInfo viewStateInfo = new ViewStateParser(helpers).parseResponse(responseInfo, responseWithViewStateStr.getBytes(UTF_8));

        int expectedValueStart = responseWithViewStateStr.indexOf("value=\"") + 7;
        int expectedValueEnd = responseWithViewStateStr.indexOf("\"/>", expectedValueStart);

        assertThat(viewStateInfo.from).isEqualTo(expectedValueStart);
        assertThat(viewStateInfo.to).isEqualTo(expectedValueEnd);

        assertThat(viewStateInfo.viewState).isNotNull();
        assertThat(viewStateInfo.viewState.errorOccurred).isFalse();
        assertThat(viewStateInfo.viewState.macEnabled).isEqualTo(macEnabled);
        assertThat(viewStateInfo.viewState.version).isEqualTo(version);
        assertThat(viewStateInfo.viewState.value.toString()).isEqualTo(deserialisedViewStateValue);
    }

    private static class ViewStateParam implements IParameter
    {
        private final String viewstate;

        ViewStateParam(String viewstate)
        {
            this.viewstate = viewstate;
        }

        @Override
        public byte getType()
        {
            return 0;
        }

        @Override
        public String getName()
        {
            return "__VIEWSTATE";
        }

        @Override
        public String getValue()
        {
            return viewstate;
        }

        @Override
        public int getNameStart()
        {
            return 5;
        }

        @Override
        public int getNameEnd()
        {
            return 10;
        }

        @Override
        public int getValueStart()
        {
            return 15;
        }

        @Override
        public int getValueEnd()
        {
            return 20;
        }

    }

    private static Stream<Arguments> viewStateUrlEncodedTestArgsProvider()
    {
        return Stream.of(
                Arguments.of(VIEWSTATE_1_1_URL_ENCODED, Version.V11, false, DESERIALISED_VIEW_STATE_1_1_VALUE),
                Arguments.of(VIEWSTATE_2_0_URL_ENCODED, Version.V20, true, DESERIALISED_VIEW_STATE_2_0_VALUE)
        );
    }

    private static Stream<Arguments> viewStateInResponseBodyTestArgsProvider()
    {
        return Stream.of(
                Arguments.of(VIEWSTATE_1_1, Version.V11, false, DESERIALISED_VIEW_STATE_1_1_VALUE),
                Arguments.of(VIEWSTATE_2_0, Version.V20, true, DESERIALISED_VIEW_STATE_2_0_VALUE)
        );
    }
}