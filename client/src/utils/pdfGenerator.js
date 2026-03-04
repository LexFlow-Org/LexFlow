import jsPDF from 'jspdf';
import 'jspdf-autotable';
import { exportPDF } from '../tauri-api';

const TYPE_LABELS = { civile: 'Civile', penale: 'Penale', amm: 'Amministrativo', stra: 'Stragiudiziale' };
const FIELD_LABELS = {
  civile:  { counterparty: 'Controparte',    court: 'Tribunale',   code: 'N. R.G.' },
  penale:  { counterparty: 'Parte Offesa',   court: 'Tribunale',   code: 'N. R.G.N.R.' },
  amm:     { counterparty: 'Amministrazione', court: 'TAR / CdS', code: 'N. Ricorso' },
  stra:    { counterparty: 'Controparte',    court: 'Sede',        code: 'Rif. Pratica' },
};

/** Safe date formatter — returns fallback on invalid dates */
function safeDateIT(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('it-IT');
}

// Funzione di generazione grafica (Layout)
export function generatePracticePDF(practice) {
  // Orientamento verticale, millimetri, A4
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const labels = FIELD_LABELS[practice.type] || FIELD_LABELS.civile;
  const pageW = doc.internal.pageSize.getWidth();
  let y = 20;

  // ===== Header =====
  doc.setFillColor(13, 14, 22); // Background scuro
  doc.rect(0, 0, pageW, 40, 'F');

  doc.setTextColor(128, 112, 208); // Primary Color
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.text('LEXFLOW', 20, y + 4);

  doc.setTextColor(200, 200, 220);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('Report Fascicolo', 20, y + 12);

  doc.setTextColor(180, 180, 200);
  doc.setFontSize(8);
  doc.text(`Generato il ${new Date().toLocaleDateString('it-IT')}`, pageW - 20, y + 4, { align: 'right' });

  y = 50;

  // ===== Info Fascicolo =====
  doc.setTextColor(50, 50, 70);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('Dati del Fascicolo', 20, y);
  y += 8;

  const info = [
    ['Tipo', TYPE_LABELS[practice.type] || practice.type],
    ['Cliente / Assistito', practice.client || '-'],
    [labels.counterparty, practice.counterparty || '-'],
    [labels.court, practice.court || '-'],
    [labels.code, practice.code || '-'],
    ['Oggetto', practice.object || '-'],
    ['Stato', practice.status === 'active' ? 'Attivo' : 'Chiuso'],
  ];

  doc.autoTable({
    startY: y,
    body: info,
    theme: 'plain',
    styles: { fontSize: 9, cellPadding: 3 },
    columnStyles: {
      0: { fontStyle: 'bold', textColor: [100, 100, 120], cellWidth: 50 },
      1: { textColor: [40, 40, 60] },
    },
    margin: { left: 20, right: 20 },
  });

  y = doc.lastAutoTable.finalY + 12;

  // ===== Scadenze =====
  if (practice.deadlines && practice.deadlines.length > 0) {
    doc.setFontSize(13);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(50, 50, 70);
    doc.text('Scadenze', 20, y);
    y += 6;

    doc.autoTable({
      startY: y,
      head: [['Data', 'Scadenza']],
      body: practice.deadlines.map(d => [
        safeDateIT(d.date),
        d.label,
      ]),
      styles: { fontSize: 9, cellPadding: 3 },
      headStyles: { fillColor: [128, 112, 208], textColor: [255, 255, 255], fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [245, 245, 250] },
      margin: { left: 20, right: 20 },
    });

    y = doc.lastAutoTable.finalY + 12;
  }

  // ===== Attività (Tasks) =====
  if (practice.tasks && practice.tasks.length > 0) {
    // Controllo fine pagina
    if (y > 240) { doc.addPage(); y = 20; }
    
    doc.setFontSize(13);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(50, 50, 70);
    doc.text('Attività (To-Do)', 20, y);
    y += 6;

    doc.autoTable({
      startY: y,
      head: [['Stato', 'Attività']],
      body: practice.tasks.map(t => [
        t.done ? '✓ Completata' : '○ Pendente',
        t.text,
      ]),
      styles: { fontSize: 9, cellPadding: 3 },
      headStyles: { fillColor: [128, 112, 208], textColor: [255, 255, 255], fontStyle: 'bold' },
      columnStyles: { 0: { cellWidth: 35 } },
      alternateRowStyles: { fillColor: [245, 245, 250] },
      margin: { left: 20, right: 20 },
    });

    y = doc.lastAutoTable.finalY + 12;
  }

  // ===== Diario =====
  if (practice.diary && practice.diary.length > 0) {
    if (y > 220) { doc.addPage(); y = 20; }
    
    doc.setFontSize(13);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(50, 50, 70);
    doc.text('Diario Attività', 20, y);
    y += 6;

    doc.autoTable({
      startY: y,
      head: [['Data', 'Annotazione']],
      body: practice.diary.map(d => [
        safeDateIT(d.date),
        d.text,
      ]),
      styles: { fontSize: 9, cellPadding: 3 },
      headStyles: { fillColor: [128, 112, 208], textColor: [255, 255, 255], fontStyle: 'bold' },
      columnStyles: { 0: { cellWidth: 30 } },
      alternateRowStyles: { fillColor: [245, 245, 250] },
      margin: { left: 20, right: 20 },
    });
  }

  // ===== Footer (Numeri Pagina) =====
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(160, 160, 180);
    doc.text(
      `LexFlow — Documento riservato — Pagina ${i} di ${pageCount}`,
      pageW / 2, doc.internal.pageSize.getHeight() - 8,
      { align: 'center' }
    );
  }

  return doc;
}

// Funzione di Esportazione Sicura (Interfacciata con API Electron)
export async function exportPracticePDF(practice) {
  try {
    // 1. Genera il documento PDF in memoria
    const doc = generatePracticePDF(practice);
    
    // 2. Prepara il nome del file pulito
    const clientSafe = (practice.client || 'fascicolo')
      .replaceAll(/[^a-zA-Z0-9àèéìòù ]/g, '')
      .trim()
      .replaceAll(/\s+/g, '_');
      
    const defaultName = `LexFlow_${clientSafe}_${new Date().toISOString().split('T')[0]}.pdf`;

    // 3. Genera l'ArrayBuffer (Dati grezzi)
    const pdfArrayBuffer = doc.output('arraybuffer');

    // 4. Chiama il Backend Sicuro
    // Non chiediamo il path qui. Il Main Process aprirà il dialogo di salvataggio
    // e scriverà il file solo se l'utente conferma.
    const result = await exportPDF(pdfArrayBuffer, defaultName);

    return result.success;
  } catch (error) {
    console.error("Errore critico export PDF:", error);
    return false;
  }
}