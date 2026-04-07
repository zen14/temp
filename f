import org.jmrtd.*;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.DG1File;

import javax.smartcardio.*;
import java.io.InputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ReadEID {

    private static final String CAN = "123456"; // <-- OVDJE STAVI SVOJ CAN

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ReadEID().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {
                List<CardTerminal> terminals = factory.terminals().list();

                for (CardTerminal terminal : terminals) {

                    if (terminal.isCardPresent()) {
                        System.out.println("📇 Kartica detektovana: " + terminal.getName());

                        readCard(terminal);

                        while (terminal.isCardPresent()) {
                            Thread.sleep(500);
                        }

                        System.out.println("📤 Kartica uklonjena\n");
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void readCard(CardTerminal terminal) {
        try {
            Card card = terminal.connect("T=CL");
            CardService service = CardService.getInstance(card);
            service.open();

            PassportService ps = new PassportService(service);
            ps.open();

            System.out.println("🔐 Pokrećem PACE...");

            // PACE sa CAN
            BACKeySpec paceKey = new BACKey(CAN, "", "");

            ps.doPACE(paceKey, null);

            System.out.println("✅ PACE uspješan!");

            ps.sendSelectApplet(false);

            // Čitanje DG1 (osnovni podaci)
            InputStream dg1Stream = ps.getInputStream(PassportService.EF_DG1);
            DG1File dg1 = new DG1File(dg1Stream);

            System.out.println("📄 DG1 sadržaj:");
            System.out.println(dg1.getMRZInfo().toString());

        } catch (Exception e) {
            System.out.println("❌ Greška pri čitanju kartice");
            e.printStackTrace();
        }
    }
}


import javax.smartcardio.*;
import java.util.List;

public class SmartCardFullListener {

    public static void main(String[] args) {
        new SmartCardFullListener().start();
    }

    public void start() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();

            while (true) {

                List<CardTerminal> terminals = factory.terminals().list();

                if (terminals.isEmpty()) {
                    System.out.println("❌ Nema readera...");
                    Thread.sleep(2000);
                    continue;
                }

                // Ispiši sve readere
                System.out.println("\n📡 Dostupni readeri:");
                for (int i = 0; i < terminals.size(); i++) {
                    System.out.println(i + ": " + terminals.get(i).getName());
                }

                // Prođi kroz sve readere (kontakt + NFC)
                for (CardTerminal terminal : terminals) {

                    try {
                        if (terminal.isCardPresent()) {
                            System.out.println("\n📇 Kartica detektovana na: " + terminal.getName());

                            processCard(terminal);

                            // čekaj da se kartica makne
                            while (terminal.isCardPresent()) {
                                Thread.sleep(500);
                            }

                            System.out.println("📤 Kartica uklonjena\n");
                        }

                    } catch (Exception e) {
                        System.out.println("⚠️ Greška na readeru: " + terminal.getName());
                    }
                }

                Thread.sleep(500);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void processCard(CardTerminal terminal) {
        Card card = null;

        try {
            // pokušaj različite protokole (bitno za NFC!)
            String[] protocols = {"T=0", "T=1", "T=CL", "*"};

            for (String protocol : protocols) {
                try {
                    card = terminal.connect(protocol);
                    System.out.println("🔗 Spojen preko protokola: " + protocol);
                    break;
                } catch (Exception ignored) {}
            }

            if (card == null) {
                System.out.println("❌ Ne mogu se spojiti na karticu");
                return;
            }

            CardChannel channel = card.getBasicChannel();

            System.out.println("📨 Slanje test APDU komande...");

            byte[] command = new byte[]{
                    (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x00
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
<dependencies>
    <dependency>
        <groupId>org.jmrtd</groupId>
        <artifactId>jmrtd</artifactId>
        <version>0.7.42</version>
    </dependency>
</dependencies>
<dependencies>
    <dependency>
        <groupId>org.jmrtd</groupId>
        <artifactId>jmrtd</artifactId>
        <version>0.7.42</version>
    </dependency>

    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.78</version>
    </dependency>
</dependencies>

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
