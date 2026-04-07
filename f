import javax.smartcardio.*;
import java.util.List;

public class SmartCardListener {

    public static void main(String[] args) {
        new SmartCardListener().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            if (terminals.isEmpty()) {
                System.out.println("❌ Nema dostupnih čitača kartica.");
                return;
            }

            CardTerminal terminal = terminals.get(0);
            System.out.println("✅ Reader pronađen: " + terminal.getName());

            while (true) {
                System.out.println("⏳ Čekam karticu...");

                // BLOKIRA dok se kartica ne prisloni
                terminal.waitForCardPresent(0);

                System.out.println("📇 Kartica detektovana!");

                processCard(terminal);

                // Čekaj da korisnik makne karticu
                terminal.waitForCardAbsent(0);
                System.out.println("📤 Kartica uklonjena\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processCard(CardTerminal terminal) {
        Card card = null;

        try {
            card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();

            System.out.println("🔗 Povezan sa karticom");

            // TODO: Ovdje ide prava logika (BAC/PACE + čitanje podataka)
            byte[] command = new byte[] {
                (byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x00
            };

            ResponseAPDU response = channel.transmit(new CommandAPDU(command));

            System.out.println("📥 Response: " + bytesToHex(response.getBytes()));

        } catch (Exception e) {
            System.out.println("❌ Greška pri radu s karticom");
            e.printStackTrace();
        } finally {
            try {
                if (card != null) {
                    card.disconnect(false);
                }
            } catch (Exception ignored) {}
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
