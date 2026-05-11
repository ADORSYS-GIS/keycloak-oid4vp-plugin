package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import javax.imageio.ImageIO;

public class QRCodeTestUtils {

    public static String decodeQrCodeFromDataUrl(String src) {
        try {
            // Strip data URL prefix
            // Example input: data:image/png;base64,iVBORw0KGgoAAAANS...
            String base64 = src.substring(src.indexOf(",") + 1);

            // Decode base64
            byte[] imageBytes = Base64.getDecoder().decode(base64);

            // Read image
            BufferedImage bufferedImage = ImageIO.read(new ByteArrayInputStream(imageBytes));

            // Convert for ZXing
            LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

            // Decode QR
            Result result = new MultiFormatReader().decode(bitmap);
            return result.getText();
        } catch (Exception e) {
            throw new RuntimeException("QR code decoding failed", e);
        }
    }
}
