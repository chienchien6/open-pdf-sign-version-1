
command: mvn clean package -DskipTests跳過測試執行打包命令
          
您好！要使用 HSM 簽署 PDF 並在 PDF 上顯示簽署人、時間戳和圖片，您需要透過命令列介面執行此應用程式，並提供相應的參數。

假設您的應用程式打包成一個名為 `open-pdf-sign.jar` 的 JAR 檔案，並且主類別是 `org.openpdfsign.Main`（這可能需要根據您的專案設定進行調整），一個範例命令可能如下所示：

```bash
java -jar open-pdf-sign.jar \
    -i "C:\path\to\your\input.pdf" \
    -o "C:\path\to\your\output_signed.pdf" \
    --hsm-lib "C:\path\to\your\pkcs11_library.dll" \
    --hsm-pin "YOUR_HSM_PIN" \
    --hsm-slot "SLOT_ID" \
    --hsm-key-alias "YOUR_KEY_ALIAS" \
    --page 1 \
    --left 10 \
    --top 10 \
    --width 50 \
    --image "C:\path\to\your\signature_image.png" \
    --hint "test112233445566" \
    --label-signee "Signer Name:" \
    --label-timestamp "Timestamp:" 
    --tsa http://your-timestamp-authority.com
    --right 1 表示簽名框右邊緣距離頁面右邊緣1cm。```
    --top -2 (用-2就可以達到botton)

**請注意替換以下預留位置為您的實際值：**

*   `C:\path\to\your\input.pdf`: 您要簽署的 PDF 檔案路徑。
*   `C:\path\to\your\output_signed.pdf`: 簽署後輸出的 PDF 檔案路徑。
*   `C:\path\to\your\pkcs11_library.dll`: 您的 HSM PKCS#11 程式庫檔案路徑（例如，`.dll` on Windows, `.so` on Linux）。
*   `YOUR_HSM_PIN`: 您的 HSM PIN 碼。
*   `SLOT_ID`: 您的 HSM 插槽 ID。
*   `YOUR_KEY_ALIAS`: 您要在 HSM 中使用的金鑰別名。
*   `--page 1`: 簽名要放置的頁碼。
*   `--left 10 --top 10 --width 50`: 簽名圖片在頁面上的位置（左邊距、上邊距、寬度，單位通常是 mm）。這些值會被轉換為 PDF 點（1mm 約等於 2.83點，但程式碼中使用 7.2f 的轉換因子，這似乎是基於 72 DPI 下 1 inch = 25.4 mm，1 point = 1/72 inch，所以 1mm = (1/25.4) * 72 points ≈ 2.83 points。程式碼中的 `* 7.2f` 可能是個錯誤或者有特定原因，如果位置不對，您可能需要調整這些值*   `C:\path\to\your\signature_image.png`: 您要顯示的簽名圖片路徑。
*   `--hint "Signed by: {signer}\nDate: {timestamp}"`: 簽名提示文字，其中 `{signer}` 和 `{timestamp}` 是預留位置，會被實際的簽署人名稱和簽署日期取代。您可以自訂此文字。
*   `--label-signee "Signer Name:"`: 簽署人標籤文字。
*   `--label-timestamp "Timestamp:"`: 時間戳標籤文字。
*   `--tsa http://your-timestamp-authority.com`: (可選) 如果您需要使用特定的時間戳伺服器，請取消註解並提供 URL。
* --right 1 表示簽名框右邊緣距離頁面右邊緣1cm。
* --right 0 
* --top -2 (用-2就可以達到botton)

**重要提示：**

1.  **JAR 檔案名稱和主類別**：請確認 `open-pdf-sign.jar` 和主類別名稱是否正確。


下方為簽屬PAdES B-LT 為--baseline-lt 的command:
java -jar openpdfsign.jar --input ruiting.pdf --output output.pdf --hsm-library "C:/OpenAPI GatewayRT/Go/lib/V4.55.0.0/Windows/x86-64/cs_pkcs11_R3.dll" --hsm-pin 12345678 --hsm-slot 0 --hsm-key-alias "ECC Private Key" --baseline-lt --timestamp --tsa http://timestamp.digicert.com --page 1 --right 0 --top -2 --width 10 --image signature.png --hint "test112233445566BLT"

簽署LTA 即改成 --baseline-lta
java -jar openpdfsign.jar --input ruiting.pdf --output output.pdf --hsm-library "C:/OpenAPI GatewayRT/Go/lib/V4.55.0.0/Windows/x86-64/cs_pkcs11_R3.dll" --hsm-pin 12345678 --hsm-slot 0 --hsm-key-alias "ECC Private Key" --baseline-lta --timestamp --tsa http://timestamp.digicert.com --page 1 --right 0 --top -2 --width 10 --image signature.png --hint "test112233445566LTA"


簽署PAdES B-B 即不需要--baseline 跟--timestamp flag
java -jar openpdfsign.jar --input ruiting.pdf --output output.pdf --hsm-library "C:/OpenAPI GatewayRT/Go/lib/V4.55.0.0/Windows/x86-64/cs_pkcs11_R3.dll" --hsm-pin 12345678 --hsm-slot 0 --hsm-key-alias "ECC Private Key" --page 1 --right 0 --top -2 --width 10 --image starfish.jpg --hint "test112233445566BB"


簽署PAdES B-T 即不需要--baseline 
java -jar openpdfsign.jar --input ruiting.pdf --output output.pdf --hsm-library "C:/OpenAPI GatewayRT/Go/lib/V4.55.0.0/Windows/x86-64/cs_pkcs11_R3.dll" --hsm-pin 12345678 --hsm-slot 0 --hsm-key-alias "ECC Private Key" --timestamp --tsa http://timestamp.digicert.com --page -1 --right 0 --top -2 --width 10 --image starfish.jpg --hint "test112233445566BT"




