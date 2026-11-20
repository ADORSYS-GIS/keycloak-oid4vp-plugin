package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.zxing.WriterException;
import java.awt.image.BufferedImage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class QrCodeDataUrlTest {

    private static final String PREFIX = "data:image/png;base64,";
    private static final int WHITE = 0xFFFFFFFF;

    @Test
    void rendersADataUrl() {
        String dataUrl = QrCodeDataUrl.render("openid4vp://authorize?client_id=demo");

        assertTrue(dataUrl.startsWith(PREFIX));
        assertEquals("openid4vp://authorize?client_id=demo", QRCodeTestUtils.decodeQrCodeFromDataUrl(dataUrl));
    }

    /**
     * QRCodeWriter used to center the rounding leftover of the requested image size, which showed up as a white
     * margin that grew with the QR code density. The rendered image must not have any margin, whatever the density.
     */
    @ParameterizedTest
    @ValueSource(ints = {10, 100, 400, 800, 1500, 2500})
    void rendersQrCodeWithoutMargin(int density) {
        String request = "openid4vp://authorize?client_id=demo&request_uri=" + "a".repeat(density);

        BufferedImage image = QRCodeTestUtils.dataUrltoImage(QrCodeDataUrl.render(request));

        int[] borders = borders(image);
        assertEquals(0, borders[0], "left margin");
        assertEquals(0, borders[1], "top margin");
        assertEquals(0, borders[2], "right margin");
        assertEquals(0, borders[3], "bottom margin");

        assertEquals(image.getWidth(), image.getHeight(), "image must be square");
        assertTrue(image.getWidth() <= 300, "image must not exceed 300 px, but was " + image.getWidth() + " px");
    }

    @Test
    void rejectsContentTooLongForAnyQrCode() {
        IllegalStateException exception =
                assertThrows(IllegalStateException.class, () -> QrCodeDataUrl.render("a".repeat(10_000)));

        assertEquals("QR code creating failed", exception.getMessage());
        assertInstanceOf(WriterException.class, exception.getCause());
        assertEquals("Data too big", exception.getCause().getMessage());
    }

    /**
     * Measures the white border on the left, top, right and bottom of the image.
     */
    private static int[] borders(BufferedImage image) {
        int width = image.getWidth();
        int height = image.getHeight();
        int left = width;
        int top = height;
        int right = -1;
        int bottom = -1;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (image.getRGB(x, y) != WHITE) {
                    left = Math.min(left, x);
                    top = Math.min(top, y);
                    right = Math.max(right, x);
                    bottom = Math.max(bottom, y);
                }
            }
        }
        return new int[] {left, top, width - 1 - right, height - 1 - bottom};
    }
}
