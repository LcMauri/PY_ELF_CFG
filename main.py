import math

from PySide6.QtWidgets import QApplication, QWidget
from PySide6.QtGui import QPainter, QBrush, QColor, QFont, QPen, QPolygonF, QPainterPath
from PySide6.QtCore import Qt, QPointF, QRect, QRectF
import grapher
import disas
from collections import Counter
from collections import defaultdict

class PannableZoomableView(QWidget):
    def __init__(self,graph,dism,elf,tab):
        super().__init__()
        self.setWindowTitle("Pannable & Zoomable View")
        self.resize(1440, 900)
        self.nodes=[]
        asChild=False
        j=0
        childs=[]
        childs_tmp = []
        self.nodes.append({"pos": QPointF(1440/2, 50),"gen":0, "color": QColor("red"),"isDraggable":True,"draggin":False,"addrStart":tab.cells[tab.start].code[0],"addrEnd":tab.cells[tab.start].code[1],"link0":tab.cells[tab.start].link[0],"link1":tab.cells[tab.start].link[1],"size":0})
        if(self.nodes[0]["link0"]!=0):
            asChild=True
            childs.append(self.nodes[0]["link0"])
        if((self.nodes[0]["link1"]!=0)):
            childs.append(self.nodes[0]["link1"])
            asChild = True
        while(asChild==True):
            asChild=False
            j = j + 1
            for y in range(len(childs)):
                if(tab.cells.__contains__(childs[y])):
                    if(tab.cells[childs[y]].done==False):
                        self.nodes.append(
                            {"pos": QPointF(1440 / 2, 50+((900/8)*j)), "gen": j, "color": QColor("red"), "isDraggable": True,
                             "draggin": False, "addrStart": tab.cells[childs[y]].code[0],
                             "addrEnd": tab.cells[childs[y]].code[1],
                             "link0": tab.cells[childs[y]].link[0],
                             "link1": tab.cells[childs[y]].link[1],
                             "size":1})
                        if (tab.cells[childs[y]].link[0] != 0):
                            asChild = True
                            childs_tmp.append(tab.cells[childs[y]].link[0])
                        if ((tab.cells[childs[y]].link[1] != 0)):
                            childs_tmp.append(tab.cells[childs[y]].link[1])
                            asChild = True
                        tab.cells[childs[y]].done=True
            childs = childs_tmp
            childs_tmp=[]
        self.circle_radius = 30
        self.view_offset = QPointF(0, 0)
        self.scale = 1.0
        self.min_scale = 0.25
        self.max_scale = 3.0
        gen_counts = Counter(node["gen"] for node in self.nodes)
        self.last_mouse_pos = None
        self.panning = False
        self.drag_offset = QPointF(0, 0)

        # Layout constants
        canvas_width = 1440
        start_y = 50
        step_y = 900 / 8
        step_x = 900  # Horizontal spacing between nodes
        for node in self.nodes:
            addr=0
            addr = node["addrStart"]
            while(addr!=node["addrEnd"]):
                addr=addr+len(dism.bytes[addr])
                node["size"]=node["size"]+1

        # Group nodes by their gen
        gen_groups = defaultdict(list)
        for node in self.nodes:
            gen_groups[node["gen"]].append(node)
        # Obtenir la taille maximale par "gen"
        max_size_per_gen = {}
        for gen, nodes in gen_groups.items():
            max_size = max(node["size"] for node in nodes)
            max_size_per_gen[gen] = max_size
        # Assign positions
        cumul=0
        for gen, nodes in gen_groups.items():
            n = len(nodes)
            total_width = (n - 1) * step_x
            start_x = (canvas_width - total_width) / 2  # center the row
            y = start_y + step_y * gen+ (self.scale*30*cumul+2 * self.circle_radius * self.scale)

            for i, node in enumerate(nodes):
                x = start_x + (i * step_x)
                node["pos"] = QPointF(x, y)

            cumul = cumul + max_size_per_gen[gen]

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor("#4d4145"))


        # Apply scale and offset to transform world coords to screen coords
        def world_to_screen(world_pos):
            return (world_pos + self.view_offset) * self.scale

        for node in self.nodes:
            #define mon cercle
            node_screen_pos = world_to_screen(node["pos"])
            x = node_screen_pos.x() - self.circle_radius * self.scale
            y = node_screen_pos.y() - self.circle_radius * self.scale
            size = 2 * self.circle_radius * self.scale
            rect_width = 10 * size
            rect_height = 1.2 * size * node["size"]
            # Draw red circle (fixed)
            painter.setPen(node["color"])
            painter.setBrush(QBrush("white"))
            painter.drawRect(QRect(x,y,10*size,size+self.scale*30*node["size"]))
            # Définir la taille dynamique de la police
            font_size = max(1, int(15 * self.scale))
            font = QFont("Arial", font_size)
            painter.setFont(font)

            text_height = painter.fontMetrics().height()
            text_x = x + (20 * self.scale)
            text_y = y + text_height + (22 * self.scale)
            line_spacing = (30 * self.scale)

            # Récupérer toutes les instructions dans le node
            instructions = []
            addr = node["addrStart"]
            while True:
                instructions.append(addr)
                if addr == node["addrEnd"]:
                    break
                addr += len(dism.bytes[addr])

            # Calculer la largeur max des bytes
            max_bytes_width = 0
            for addr in instructions:
                byte_text = dism.bytes[addr].hex()
                w = painter.fontMetrics().horizontalAdvance(byte_text)
                if w > max_bytes_width:
                    max_bytes_width = w

            # Calculer la largeur max des mnemonics
            max_mnemonic_width = 0
            for addr in instructions:
                mnemonic_text = dism.mnemonic[addr]
                w = painter.fontMetrics().horizontalAdvance(mnemonic_text)
                if w > max_mnemonic_width:
                    max_mnemonic_width = w

            padding = painter.fontMetrics().horizontalAdvance("   ")  # largeur d’un espace

            x_bytes = text_x
            x_mnemonic = x_bytes + max_bytes_width + padding
            x_op_str = x_mnemonic + max_mnemonic_width + padding + 10

            # Dessiner les lignes
            for i, addr in enumerate(instructions):
                ypos = text_y + line_spacing * i

                # Bytes en bleu
                painter.setPen(QColor("blue"))
                painter.drawText(x_bytes, ypos, dism.bytes[addr].hex())

                # Mnemonic en noir, aligné
                painter.setPen(QColor("black"))
                painter.drawText(x_mnemonic, ypos, dism.mnemonic[addr])

                # op_str en rouge, aligné
                painter.setPen(QColor("red"))
                painter.drawText(x_op_str, ypos, dism.op_str[addr])
                # Draw arrows between nodes
                for parent in self.nodes:
                    parent_screen_pos = world_to_screen(parent["pos"])
                    size = 2 * self.circle_radius * self.scale
                    rect_width = 10 * size
                    rect_height = size + self.scale * 30 * parent["size"]
                    parent_rect_x = parent_screen_pos.x() - self.circle_radius * self.scale
                    parent_rect_y = parent_screen_pos.y() - self.circle_radius * self.scale

                    for i, link_key in enumerate(["link0", "link1"]):
                        child_addr = parent[link_key]
                        if child_addr == 0:
                            continue

                        child = next((n for n in self.nodes if n["addrStart"] == child_addr), None)
                        if not child:
                            continue

                        child_screen_pos = world_to_screen(child["pos"])
                        child_size = 2 * self.circle_radius * self.scale
                        child_rect_width = 10 * child_size
                        child_rect_height = child_size + self.scale * 30 * child["size"]

                        child_rect_x = child_screen_pos.x() - self.circle_radius * self.scale
                        child_rect_y = child_screen_pos.y() - self.circle_radius * self.scale

                        start = QPointF(
                            parent_rect_x + rect_width / 2,
                            parent_rect_y + rect_height
                        )
                        end = QPointF(
                            child_rect_x + child_rect_width / 2,
                            child_rect_y
                        )

                        color = QColor("green") if link_key == "link0" else QColor("red")
                        parent_gen = parent["gen"]
                        child_gen = child["gen"]

                        if child_gen < parent_gen or child_gen == parent_gen :
                            # Backward edge: bent arrow path
                            offset_x = 160 * self.scale
                            offset_y = 40 * self.scale
                            direction = -1 if parent["pos"].x() > child["pos"].x() else 1

                            path = QPainterPath()
                            path.moveTo(start)

                            p1 = QPointF(start.x(), start.y() + offset_y)
                            p2 = QPointF(start.x() + direction * offset_x, p1.y())
                            p3 = QPointF(p2.x(), end.y() - offset_y)
                            p4 = QPointF(end.x(), p3.y())
                            p5 = end

                            path.lineTo(p1)
                            path.lineTo(p2)
                            path.lineTo(p3)
                            path.lineTo(p4)
                            path.lineTo(p5)
                            painter.setBrush(Qt.NoBrush)

                            painter.setPen(QPen(color, 2))
                            painter.drawPath(path)
                            self.draw_arrow_head(painter, p4, p5, color)

                        else:
                            # Normal straight arrow
                            painter.setPen(QPen(color, 2))
                            painter.drawLine(start, end)
                            self.draw_arrow_head(painter, start, end, color)

    def draw_arrow_head(self, painter, start, end, color):
        angle = math.atan2(end.y() - start.y(), end.x() - start.x())
        arrow_size = 10 * self.scale

        # Arrowhead triangle points
        p1 = end
        p2 = QPointF(
            end.x() - arrow_size * math.cos(angle - math.pi / 6),
            end.y() - arrow_size * math.sin(angle - math.pi / 6)
        )
        p3 = QPointF(
            end.x() - arrow_size * math.cos(angle + math.pi / 6),
            end.y() - arrow_size * math.sin(angle + math.pi / 6)
        )

        painter.setBrush(QBrush(color))
        painter.setPen(QPen(color))
        painter.drawPolygon(QPolygonF([p1, p2, p3]))

    def mousePressEvent(self, event):
        self.last_mouse_pos = event.position()  # QPointF
        for node in self.nodes:
            if node["isDraggable"]:
                # Position et taille du rectangle à l'écran (avec scale et offset)
                node_screen_pos = (node["pos"] + self.view_offset) * self.scale

                width = 10 * 2 * self.circle_radius * self.scale
                height = (2 * self.circle_radius + 30 * node["size"]) * self.scale

                rect = QRectF(node_screen_pos.x() - self.circle_radius * self.scale,
                              node_screen_pos.y() - self.circle_radius * self.scale,
                              width,
                              height)

                if rect.contains(event.position()):
                    node["draggin"] = True
                    self.drag_offset = event.position() - node_screen_pos
                    return
        if event.button() == Qt.LeftButton:
            self.panning = True

    def mouseMoveEvent(self, event):
        pos = event.position()
        for node in self.nodes:
            if node["draggin"]==True:
                new_screen_pos = pos - self.drag_offset
                # Convert back to world coords:
                node["pos"] = new_screen_pos / self.scale - self.view_offset
                self.update()
        if self.panning:
            delta = pos - self.last_mouse_pos
            self.view_offset += delta / self.scale
            self.last_mouse_pos = pos
            self.update()

    def mouseReleaseEvent(self, event):
        for node in self.nodes:
            node["draggin"] = False
            self.panning = False

    def wheelEvent(self, event):
        # Zoom in/out
        angle = event.angleDelta().y()
        zoom_factor = 1.1 if angle > 0 else 0.9

        old_scale = self.scale
        new_scale = self.scale * zoom_factor

        # Clamp scale
        if new_scale < self.min_scale:
            new_scale = self.min_scale
        elif new_scale > self.max_scale:
            new_scale = self.max_scale

        # Adjust view_offset to zoom around the mouse cursor position
        mouse_pos = event.position()
        mouse_world_before = (mouse_pos / old_scale) - self.view_offset
        mouse_world_after = (mouse_pos / new_scale) - self.view_offset
        self.view_offset += (mouse_world_after - mouse_world_before)

        self.scale = new_scale
        self.update()
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QSplitter,
    QScrollArea, QApplication
)
from PySide6.QtCore import Qt


class GraphViewer(QWidget):
    def __init__(self, graph, dism, elf):
        super().__init__()
        self.setWindowTitle("Visualiseur de Graphe")
        self.resize(1600, 900)

        self.graph = graph
        self.dism = dism
        self.elf = elf

        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        # --- Zone de gauche : liste des tabs ---
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        for tab in self.graph.tab:
            btn = QPushButton(tab.name)
            btn.clicked.connect(lambda checked, t=tab: self.load_graph(t))
            left_layout.addWidget(btn)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(left_widget)

        splitter.addWidget(scroll_area)

        # --- Zone de droite : affichage du graphe ---
        self.right_container = QWidget()
        self.right_layout = QVBoxLayout(self.right_container)
        self.graph_view = None  # PannableZoomableView courant

        splitter.addWidget(self.right_container)
        splitter.setStretchFactor(1, 1)
        self.load_graph(graph.tab[0])
    def load_graph(self, tab):
        # Supprimer l'ancien graphe
        if self.graph_view is not None:
            self.graph_view.setParent(None)
            self.graph_view.deleteLater()
        for cells in tab.cells:
            tab.cells[cells].done=False
        # Créer un nouveau graphe pour le tab sélectionné
        self.graph_view = PannableZoomableView(self.graph, self.dism, self.elf, tab)
        self.right_layout.addWidget(self.graph_view)
if __name__ == "__main__":
    import sys
    import argparse
    from elftools.elf.elffile import ELFFile
    from PySide6.QtWidgets import QApplication

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="The name of the file you want to nootsbug")
    args = parser.parse_args()

    with open(args.file, mode='rb') as f:
        elffile = ELFFile(f)
        dism = disas.Dism(elffile)
        graph = grapher.Graph(dism, elffile)

        app = QApplication(sys.argv)
        window = GraphViewer(graph, dism, elffile)
        window.show()
        sys.exit(app.exec())
