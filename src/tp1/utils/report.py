import matplotlib.pyplot as plt  # type: ignore
from reportlab.lib.pagesizes import letter  # type: ignore
from reportlab.platypus import ( # type: ignore
    SimpleDocTemplate, Paragraph, Spacer, Image
)  # type: ignore
from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
from reportlab.platypus import Table, TableStyle  # type: ignore
from reportlab.lib import colors                  # type: ignore

class Report:
    def __init__(self, capture, filename, summary):
        self.capture = capture
        self.filename = filename
        self.title = "Report of network traffic capture\n"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title + "\n\n"
        content += self.summary + "\n\n"
        content += self.array + "\n\n"
        content += self.graph + "\n\n"
        return content

    def save(self, filename: str = None) -> None:
        """
        Génère un vrai PDF : titre, résumé, image, tableau.
        Vous appelez préalablement generate("graph") et generate("array").
        """
        if filename:
            self.filename = filename
        doc = SimpleDocTemplate(self.filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        elements.append(Paragraph(self.title, styles['Title']))
        elements.append(Spacer(1, 12))
        if self.summary:
            safe_summary = self.summary.replace("\n", "<br/>")
            elements.append(Paragraph(safe_summary, styles['Normal']))
            elements.append(Spacer(1, 12))
        if self.graph:
            elements.append(Image(self.graph, width=400, height=300))
            elements.append(Spacer(1, 24))
        if self.array:
            lines = self.array.strip().split("\n")
            data = [line.split("\t") for line in lines]

            table = Table(data, hAlign='CENTER', colWidths=[200, 150])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                ('TEXTCOLOR',   (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN',       (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE',    (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID',        (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME',    (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE',    (0, 1), (-1, -1), 10),
            ]))
            elements.append(table)
        doc.build(elements)
        

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            labels = list(self.capture.protocols.keys())
            sizes = list(self.capture.protocols.values())
            plt.figure(figsize=(10, 6))
            plt.bar(labels, sizes, color='skyblue')
            plt.xlabel('Protocols')
            plt.ylabel('Count')
            plt.title('Protocols Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig("protocols.png")
            plt.close()
            graph = "protocols.png"
            self.graph = graph
        elif param == "array":
            array = "Protocols\tcount\n"
            for proto, count in self.capture.protocols.items():
                array += f"{proto}\t{count}\n"
            self.array = array
        else:
            print("Invalid parameter. Please choose 'graph' or 'array'.")
