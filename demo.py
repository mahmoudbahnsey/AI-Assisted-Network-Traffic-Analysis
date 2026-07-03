"""
Demo script to run the pipeline without Zeek
"""

from main import NetworkTrafficAnalysisPipeline
import pandas as pd

def main():
    # Create pipeline
    pipeline = NetworkTrafficAnalysisPipeline()
    
    print("="*60)
    print("AI-Assisted Network Traffic Analysis - Demo")
    print("="*60)
    
    # Step 1: Parse PCAP directly (without Zeek)
    print("\n[Step 1] Parsing PCAP file directly...")
    pcap_file = "data\\raw\\attack_syn_flood_20260701_085320.pcap"
    
    try:
        flow_df = pipeline.parse_pcap_directly(pcap_file)
        print(f"✓ Parsed {len(flow_df)} flows from PCAP")
        print(f"  Features: {list(flow_df.columns)}")
    except Exception as e:
        print(f"✗ Error parsing PCAP: {e}")
        return
    
    # Step 2: Detect attacks using statistical methods
    print("\n[Step 2] Detecting attacks using statistical analysis...")
    try:
        attacks = pipeline.detector.detect_statistical(flow_df)
        print(f"✓ Detected {len(attacks)} potential attacks")
        
        for i, attack in enumerate(attacks[:5]):  # Show first 5
            print(f"  Attack {i+1}: {attack['type']} from {attack['src_ip']} (confidence: {attack['confidence']:.2f})")
    except Exception as e:
        print(f"✗ Error detecting attacks: {e}")
        return
    
    # Step 3: Display flow statistics
    print("\n[Step 3] Flow Statistics:")
    print(f"  Total flows: {len(flow_df)}")
    if 'packet_count' in flow_df.columns:
        print(f"  Avg packets per flow: {flow_df['packet_count'].mean():.2f}")
        print(f"  Max packets per flow: {flow_df['packet_count'].max()}")
    if 'byte_count' in flow_df.columns:
        print(f"  Avg bytes per flow: {flow_df['byte_count'].mean():.2f}")
        print(f"  Max bytes per flow: {flow_df['byte_count'].max()}")
    
    # Step 4: Display top suspicious flows
    print("\n[Step 4] Top Suspicious Flows (by packet count):")
    if 'packet_count' in flow_df.columns:
        top_flows = flow_df.nlargest(5, 'packet_count')
        for idx, flow in top_flows.iterrows():
            print(f"  {flow.get('src_ip', 'N/A')} -> {flow.get('dst_ip', 'N/A')}: {flow['packet_count']} packets")
    
    print("\n" + "="*60)
    print("Demo completed successfully!")
    print("="*60)

if __name__ == "__main__":
    main()
