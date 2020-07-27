package attacks;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AttackerUtil {
	
	/**
	 * compute the number of attacker nodes
	 * @param vexnum
	 * @return
	 */
	public static int getAttackerNum(double level ,int vexnum){
		return (int) Math.round(level*Math.log10(vexnum));
		//return (int) Math.round(Math.log10(vexnum)*Math.log10(vexnum));
	}
	
	public static int getMaxAttackerNum(int vexnum){
		return (int) Math.round(Math.log10(vexnum));
		//return (int) Math.round(Math.log10(vexnum)*Math.log10(vexnum));
	}

	/**
	 * 
	 * @param combines  
	 * @param aggressorNum 
	 */
	public static void getCombine(List<int[]> combines ,int aggressorNum){
		String[] aggressors = new String[aggressorNum];
		/*Trujillo- Jan 27, 2016
		 * Gives to the ith agressor the dentifier i+1*/
		for(int i=1;i<=aggressors.length;i++){
			aggressors[i-1] = String.valueOf(i);
		}
		for(int i=0;i<=aggressors.length;i++){
			String[] res=new String[i];
			combine(combines,aggressors,0,res,0);
		}
		
	}
	
	public static void combine(List<int[]> combines, final String[] a, final int a_pos, final String[] rs, final int rs_pos){ 
		if(rs_pos>=rs.length){
			if(rs.length>0){
				int[] temp = new int[rs.length];
				for(int i=0;i<rs.length;i++){
					 temp[i] = Integer.parseInt(rs[i]);
				}
				combines.add(temp);
			}
		}else{ 
			for(int ap=a_pos; ap<a.length; ap++){ 
				rs[rs_pos]=a[ap]; combine(combines,a,ap+1,rs,rs_pos+1); 
			}
		} 
	} 
	
	public static void main(String[] args) {
		List<int[]> combines = new ArrayList<int[]>();
		
		getCombine(combines,4);
		
		for(int[] temp : combines){
//			System.out.println(Arrays.toString(temp));
		}
	}
}
