https://github.com/tesseract-ocr/tesseract/wiki/Downloads/f63358fb6dbc277c0a497615d786cb2d30922bec?utm_source=chatgpt.comtest
// ================= BACKEND (Spring Boot) ================= // Maven dependencies (pom.xml) /* <dependencies> <dependency> <groupId>org.springframework.boot</groupId> <artifactId>spring-boot-starter-web</artifactId> </dependency> <dependency> <groupId>net.sourceforge.tess4j</groupId> <artifactId>tess4j</artifactId> <version>5.4.0</version> </dependency> <dependency> <groupId>com.fasterxml.jackson.core</groupId> <artifactId>jackson-databind</artifactId> </dependency> </dependencies> */

// ===== MODEL ===== class TemplateField { public String key; public double x; public double y; public double width; public double height; }

class Template { public Long id; public String name; public int imageWidth; public int imageHeight; public List<TemplateField> fields; }

// ===== CONTROLLER ===== @RestController @RequestMapping("/api/ocr") public class OCRController {

private Map<Long, Template> templates = new HashMap<>();
private AtomicLong counter = new AtomicLong();

@PostMapping("/template")
public Template saveTemplate(@RequestBody Template template) {
    template.id = counter.incrementAndGet();
    templates.put(template.id, template);
    return template;
}

@PostMapping("/extract/{templateId}")
public Map<String, String> extract(
        @PathVariable Long templateId,
        @RequestParam("file") MultipartFile file) throws Exception {

    Template template = templates.get(templateId);
    BufferedImage image = ImageIO.read(file.getInputStream());

    Tesseract tesseract = new Tesseract();
    tesseract.setDatapath("./tessdata");

    Map<String, String> result = new HashMap<>();

    for (TemplateField field : template.fields) {
        int x = (int)(field.x * image.getWidth());
        int y = (int)(field.y * image.getHeight());
        int w = (int)(field.width * image.getWidth());
        int h = (int)(field.height * image.getHeight());

        BufferedImage sub = image.getSubimage(x, y, w, h);
        String text = tesseract.doOCR(sub);

        result.put(field.key, text.trim());
    }

    return result;
}

}

// ================= FRONTEND (Angular) ================= // Install fabric.js // npm install fabric

// ===== COMPONENT ===== import { Component, ViewChild, ElementRef } from '@angular/core'; import { fabric } from 'fabric'; import axios from 'axios';

@Component({ selector: 'app-ocr', template: <input type="file" (change)="onUpload($event)"> <canvas #canvas width="800" height="600"></canvas> <button (click)="saveTemplate()">Save Template</button> }) export class OCRComponent {

@ViewChild('canvas', { static: true }) canvasRef!: ElementRef; canvas!: fabric.Canvas; fields: any[] = [];

ngOnInit() { this.canvas = new fabric.Canvas(this.canvasRef.nativeElement);

this.canvas.on('mouse:down', (o: any) => {
  const pointer = this.canvas.getPointer(o.e);

  const rect = new fabric.Rect({
    left: pointer.x,
    top: pointer.y,
    width: 100,
    height: 50,
    fill: 'rgba(0,0,255,0.3)'
  });

  this.canvas.add(rect);

  const key = prompt('Enter key:');

  this.fields.push({
    key,
    x: rect.left! / this.canvas.width!,
    y: rect.top! / this.canvas.height!,
    width: rect.width! / this.canvas.width!,
    height: rect.height! / this.canvas.height!
  });
});

}

onUpload(event: any) { const file = event.target.files[0]; const reader = new FileReader();

reader.onload = (e: any) => {
  fabric.Image.fromURL(e.target.result, (img) => {
    this.canvas.setBackgroundImage(img, this.canvas.renderAll.bind(this.canvas), {
      scaleX: this.canvas.width! / img.width!,
      scaleY: this.canvas.height! / img.height!
    });
  });
};

reader.readAsDataURL(file);

}

async saveTemplate() { await axios.post('http://localhost:8080/api/ocr/template', { name: 'test-template', imageWidth: this.canvas.width, imageHeight: this.canvas.height, fields: this.fields });

alert('Saved!');

} }

// ===== EXTRACT USAGE ===== // Example (Angular service or button) async extract(file: File, templateId: number) { const formData = new FormData(); formData.append('file', file);

const res = await axios.post(http://localhost:8080/api/ocr/extract/${templateId}, formData); console.log(res.data); }
