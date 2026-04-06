Pogledao sam tvoj link — to je jednostavan landing page za Netlify (hosting / static site) sa sekcijama tipa hero, pricing, testimonials itd. �
netlify-home-site.netlify.app
Napravio sam ti Angular verziju (HTML + CSS + TS) koju možeš direktno ubaciti u komponentu (npr. home.component).
📁 STRUKTURA

home/
 ├── home.component.html
 ├── home.component.css
 └── home.component.ts
🧩 home.component.html
HTML
<div class="container">

  <!-- HERO -->
  <section class="hero">
    <h1>Build, deploy & host your site</h1>
    <p>Simple, fast and powerful static hosting</p>
    <button (click)="onStart()">Get Started</button>
  </section>

  <!-- FEATURES -->
  <section class="features">
    <div class="feature" *ngFor="let f of features">
      <h3>{{ f.title }}</h3>
      <p>{{ f.desc }}</p>
    </div>
  </section>

  <!-- PRICING -->
  <section class="pricing">
    <div class="card" *ngFor="let p of plans">
      <h2>{{ p.name }}</h2>
      <h3>{{ p.price }}</h3>
      <ul>
        <li *ngFor="let item of p.features">{{ item }}</li>
      </ul>
      <button>Select</button>
    </div>
  </section>

  <!-- TESTIMONIALS -->
  <section class="testimonials">
    <div class="testimonial" *ngFor="let t of testimonials">
      <p>"{{ t.text }}"</p>
      <span>- {{ t.author }}</span>
    </div>
  </section>

  <!-- NEWSLETTER -->
  <section class="newsletter">
    <h2>Stay updated</h2>
    <input [(ngModel)]="email" placeholder="Enter email" />
    <button (click)="subscribe()">Subscribe</button>
  </section>

</div>
🎨 home.component.css
CSS
.container {
  font-family: Arial, sans-serif;
  padding: 20px;
}

/* HERO */
.hero {
  text-align: center;
  padding: 60px 20px;
  background: #111;
  color: white;
}

.hero button {
  margin-top: 20px;
  padding: 10px 20px;
  background: #00c853;
  border: none;
  color: white;
  cursor: pointer;
}

/* FEATURES */
.features {
  display: flex;
  justify-content: space-around;
  margin: 40px 0;
}

.feature {
  width: 30%;
  text-align: center;
}

/* PRICING */
.pricing {
  display: flex;
  gap: 20px;
  justify-content: center;
}

.card {
  border: 1px solid #ddd;
  padding: 20px;
  width: 250px;
  text-align: center;
}

.card button {
  margin-top: 10px;
  padding: 8px 15px;
  background: black;
  color: white;
}

/* TESTIMONIALS */
.testimonials {
  margin: 40px 0;
  text-align: center;
}

.testimonial {
  margin-bottom: 20px;
}

/* NEWSLETTER */
.newsletter {
  text-align: center;
}

.newsletter input {
  padding: 10px;
  width: 250px;
  margin-right: 10px;
}
⚙️ home.component.ts
TypeScript
import { Component } from '@angular/core';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent {

  email: string = '';

  features = [
    { title: 'Fast Hosting', desc: 'Global CDN for fast delivery' },
    { title: 'Continuous Deploy', desc: 'Auto deploy from Git' },
    { title: 'Secure', desc: 'SSL included by default' }
  ];

  plans = [
    {
      name: 'Free',
      price: '$0',
      features: ['100MB Storage', '1GB Bandwidth', 'Basic Support']
    },
    {
      name: 'Basic',
      price: '$9/month',
      features: ['1GB Storage', '100GB Bandwidth', 'SSL']
    },
    {
      name: 'Pro',
      price: '$29/month',
      features: ['100GB Storage', '1TB Bandwidth', 'Premium Support']
    }
  ];

  testimonials = [
    { text: 'Amazing platform for developers!', author: 'CTO, Company' },
    { text: 'Saved us tons of time.', author: 'Frontend Lead' }
  ];

  onStart() {
    alert('Getting started...');
  }

  subscribe() {
    console.log('Subscribed:', this.email);
    alert('Subscribed with ' + this.email);
    this.email = '';
  }
}
🔥 BONUS (bitno)
Ako koristiš ngModel, dodaj u app.module.ts:
TypeScript
import { FormsModule } from '@angular/forms';

@NgModule({
  imports: [FormsModule]
})
Ako želiš upgrade 🚀
Mogu ti ovo dodatno:
�⁠responsive (mobile ready)
�⁠Angular Material UI
�⁠routing (više stranica)
�⁠backend (Spring Boot kao što radiš)
ili �⁠1:1 pixel-perfect kopiju sajta
Samo reci 👍
