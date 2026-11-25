package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

/**
 * Renders QR codes as base64 data URLs suitable for {@code <img src="...">}.
 */
public final class QrCodeDataUrl {

    private static final String IMAGE_FORMAT = "png";
    private static final int TARGET_IMAGE_SIZE = 300;

    private QrCodeDataUrl() {}

    /**
     * Renders {@code content} as a margin-free QR code of about {@link #TARGET_IMAGE_SIZE} pixels.
     * <p>
     * {@link QRCodeWriter} is given a margin of 0, but it still shrinks the requested image size to the largest whole
     * multiple of the QR code module count and centers the leftover. That leftover grows with the QR code density and
     * looks like an unpredictable margin around the code. To prevent it, the image size requested here is an exact
     * multiple of the module count, so there is nothing left to center.
     *
     * @param content the text to encode
     * @return the image as a base64 data URL
     * @throws IllegalStateException if the QR code cannot be encoded or written
     */
    public static String render(String content) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            Map<EncodeHintType, Object> hints = Map.of(EncodeHintType.MARGIN, 0);

            // Encode without scaling to learn the exact module count of the QR code
            int modules = qrCodeWriter
                    .encode(content, BarcodeFormat.QR_CODE, 0, 0, hints)
                    .getWidth();

            // Request an exact multiple of the module count, which leaves QRCodeWriter nothing to pad
            int imageSize = modules * Math.max(1, TARGET_IMAGE_SIZE / modules);
            BitMatrix bitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE, imageSize, imageSize, hints);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, IMAGE_FORMAT, bos);
            String base64 = Base64.getEncoder().encodeToString(bos.toByteArray());

            return String.format("data:image/%s;base64,%s", IMAGE_FORMAT, base64);
        } catch (WriterException | IOException e) {
            throw new IllegalStateException("QR code creating failed", e);
        }
    }
}
