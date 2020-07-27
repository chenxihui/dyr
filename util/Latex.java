package util;

import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.TreeMap;



public abstract class Latex {
	
	public static void main(String[] args) {
	}
	
	
	/*An example:
		\begin{tabular}{ l | c || r }
		  1 & 2 & 3 \\
		  4 & 5 & 6 \\
		  7 & 8 & 9 \\
		\end{tabular}
	*/
	public static void appendTableHeader(List<TreeMap<Double, Double>> percentage, int[] attackers, 
			FileWriter writer) throws IOException{
		String newLine = System.getProperty("line.separator");
		writer.append("\\begin{table}"+newLine);
		writer.append("\\centering"+newLine);
		writer.append("\\begin{tabular}{ @{} l ");
		for (int i = 0; i < percentage.get(0).size(); i++) {
			writer.append(" c");
		}
		writer.append("  @{}}"+newLine);
		writer.append("\\toprule"+newLine);
		for (Double den : percentage.get(0).keySet()) {
			writer.append(" & \\textbf{"+den+"}");
		}
		writer.append(" \\\\ \\cmidrule(l){1-"+(percentage.get(0).size()+1)+"}"+newLine);
	}

	public static void appendData(List<TreeMap<Double, Double>> percentage, int[] attackers, FileWriter writer) throws IOException {
		String newLine = System.getProperty("line.separator");
		int pos = 0;
		for (TreeMap<Double, Double> row : percentage){
			writer.append("\\textbf{"+attackers[pos++]+"} ");
			for (Double p : row.values()){
				//now we need to add the attributes values
				writer.append(" & $"+p+"$ ");			
			}
			writer.append(" \\\\ \\cmidrule(l){1-"+(percentage.get(0).size()+1)+"}"+newLine);
		}
	}

	public static void appendTableFooter(FileWriter writer) throws IOException {		
		String newLine = System.getProperty("line.separator");
		writer.append("\\bottomrule"+newLine);
		writer.append("\\end{tabular}"+newLine);
		writer.append("\\end{table}"+newLine);
	}


}
