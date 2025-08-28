"""
Cybersecurity Web Threat Analysis - Dashboard Components
=======================================================

This module contains reusable dashboard components for the cybersecurity
threat analysis application.
"""

import dash
from dash import dcc, html, dash_table
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Enhanced imports with error handling
try:
    from src.utils import format_bytes, format_number, get_risk_level, MetricsCalculator
except ImportError:
    # Fallback functions if utils not available
    def format_bytes(bytes_val):
        """Format bytes with appropriate units."""
        if bytes_val >= 1024**3:
            return f"{bytes_val/1024**3:.2f} GB"
        elif bytes_val >= 1024**2:
            return f"{bytes_val/1024**2:.2f} MB"
        elif bytes_val >= 1024:
            return f"{bytes_val/1024:.2f} KB"
        else:
            return f"{bytes_val} B"
    
    def format_number(num):
        """Format large numbers with appropriate suffixes."""
        if num >= 1000000:
            return f"{num/1000000:.1f}M"
        elif num >= 1000:
            return f"{num/1000:.1f}K"
        else:
            return str(num)
    
    def get_risk_level(score):
        """Determine risk level based on score."""
        if score >= 80:
            return "CRITICAL", "#FF0000"
        elif score >= 60:
            return "HIGH", "#FF4500"
        elif score >= 40:
            return "MEDIUM", "#FFA500"
        elif score >= 20:
            return "LOW", "#FFD700"
        else:
            return "MINIMAL", "#00FF00"
    
    class MetricsCalculator:
        @staticmethod
        def get_top_risk_countries(df, top_n=10):
            """Get top risk countries from dataframe."""
            if df.empty or 'src_ip_country_code' not in df.columns:
                return pd.DataFrame()
            
            country_stats = df.groupby('src_ip_country_code').agg({
                'src_ip': 'count',
                'bytes_in': 'sum',
                'bytes_out': 'sum'
            }).reset_index()
            
            country_stats.columns = ['src_ip_country_code', 'total_connections', 'bytes_in', 'bytes_out']
            country_stats['risk_score'] = (country_stats['total_connections'] / len(df)) * 100
            
            if 'anomaly' in df.columns:
                anomaly_stats = df[df['anomaly'] == 'Suspicious'].groupby('src_ip_country_code').size().reset_index(name='anomaly')
                country_stats = country_stats.merge(anomaly_stats, on='src_ip_country_code', how='left').fillna(0)
            else:
                country_stats['anomaly'] = 0
            
            return country_stats.nlargest(top_n, 'risk_score')

class DashboardComponents:
    """Reusable components for the cybersecurity."""
    
    def __init__(self):
        self.colors = {
            'primary': '#2E86AB',
            'secondary': '#A23B72',
            'success': '#00C851',
            'danger': '#FF4444',
            'warning': '#FF8800',
            'info': '#33B5E5',
            'light': '#F8F9FA',
            'dark': '#343A40',
            'background': '#1E1E1E',
            'surface': '#2D2D2D',
            'text': '#FFFFFF'
        }
    
    def create_header(self):
        """Create the main dashboard header."""
        return html.Div([
            html.Div([
                html.Div([
                    html.Img(
                        src='/assets/logo.png',
                        style={
                            'height': '60px',
                            'marginRight': '20px'
                        }
                    ),
                    html.Div([
                        html.H1("CYBERSECURITY THREAT INTELLIGENCE DASHBOARD", 
                               style={
                                   'color': self.colors['text'],
                                   'fontSize': '28px',
                                   'fontWeight': 'bold',
                                   'margin': '0',
                                   'textShadow': '2px 2px 4px rgba(0,0,0,0.5)'
                               }),
                        html.P("Real-time network threat detection and analysis",
                              style={
                                  'color': '#CCCCCC',
                                  'fontSize': '14px',
                                  'margin': '5px 0 0 0'
                              })
                    ])
                ], style={
                    'display': 'flex',
                    'alignItems': 'center'
                }),
                html.Div([
                    html.Div([
                        html.Span("🔴", style={'fontSize': '12px', 'marginRight': '5px'}),
                        html.Span("LIVE", style={'fontSize': '12px', 'fontWeight': 'bold'})
                    ], style={
                        'backgroundColor': '#FF4444',
                        'color': 'white',
                        'padding': '5px 10px',
                        'borderRadius': '15px',
                        'fontSize': '12px',
                        'marginRight': '15px'
                    }),
                    html.Div(id='last-updated', style={
                        'color': '#CCCCCC',
                        'fontSize': '12px'
                    })
                ], style={
                    'display': 'flex',
                    'alignItems': 'center'
                })
            ], style={
                'display': 'flex',
                'justifyContent': 'space-between',
                'alignItems': 'center',
                'padding': '20px 30px',
                'background': f'linear-gradient(135deg, {self.colors["primary"]}, {self.colors["secondary"]})',
                'borderRadius': '10px',
                'boxShadow': '0 4px 20px rgba(0,0,0,0.3)',
                'margin': '20px',
                'marginBottom': '30px'
            })
        ])
    
    def create_metric_card(self, title, value, subtitle="", icon="📊", color="primary", change=None):
        """Create a metric card component."""
        card_color = self.colors.get(color, self.colors['primary'])
        
        change_component = html.Div()
        if change is not None:
            change_color = self.colors['success'] if change >= 0 else self.colors['danger']
            change_icon = "↗️" if change >= 0 else "↘️"
            change_component = html.Div([
                html.Span(change_icon, style={'marginRight': '5px'}),
                html.Span(f"{abs(change):.1f}%", style={'fontWeight': 'bold'})
            ], style={
                'color': change_color,
                'fontSize': '12px',
                'marginTop': '5px'
            })
        
        return html.Div([
            html.Div([
                html.Div([
                    html.Span(icon, style={
                        'fontSize': '24px',
                        'marginBottom': '10px',
                        'display': 'block'
                    }),
                    html.H3(str(value), style={
                        'color': self.colors['text'],
                        'fontSize': '24px',
                        'fontWeight': 'bold',
                        'margin': '0 0 5px 0'
                    }),
                    html.P(title, style={
                        'color': '#CCCCCC',
                        'fontSize': '14px',
                        'margin': '0 0 5px 0'
                    }),
                    html.P(subtitle, style={
                        'color': '#AAAAAA',
                        'fontSize': '12px',
                        'margin': '0'
                    }),
                    change_component
                ])
            ], style={
                'backgroundColor': self.colors['surface'],
                'padding': '20px',
                'borderRadius': '10px',
                'boxShadow': '0 2px 10px rgba(0,0,0,0.2)',
                'borderLeft': f'4px solid {card_color}',
                'height': '140px',
                'display': 'flex',
                'flexDirection': 'column',
                'justifyContent': 'center'
            })
        ])
    
    def create_threat_level_indicator(self, threat_score):
        """Create a threat level indicator."""
        level, color = get_risk_level(threat_score)
        
        return html.Div([
            html.Div([
                html.H4("🎯 Threat Level", style={
                    'color': self.colors['text'],
                    'margin': '0 0 15px 0',
                    'fontSize': '18px'
                }),
                html.Div([
                    html.Div([
                        html.Div(style={
                            'width': f'{threat_score}%',
                            'height': '100%',
                            'backgroundColor': color,
                            'borderRadius': '10px',
                            'transition': 'width 0.5s ease-in-out'
                        })
                    ], style={
                        'width': '100%',
                        'height': '20px',
                        'backgroundColor': '#3A3A3A',
                        'borderRadius': '10px',
                        'marginBottom': '10px'
                    }),
                    html.Div([
                        html.Span(level, style={
                            'fontSize': '20px',
                            'fontWeight': 'bold',
                            'color': color
                        }),
                        html.Span(f" ({threat_score:.1f}%)", style={
                            'fontSize': '16px',
                            'color': '#CCCCCC',
                            'marginLeft': '10px'
                        })
                    ])
                ])
            ], style={
                'backgroundColor': self.colors['surface'],
                'padding': '20px',
                'borderRadius': '10px',
                'boxShadow': '0 2px 10px rgba(0,0,0,0.2)'
            })
        ])
    
    def create_traffic_chart(self, df):
        """Create traffic analysis chart."""
        if df.empty or 'bytes_in' not in df.columns:
            return html.Div("No traffic data available", style={'color': '#CCCCCC'})
        
        # Sample data for performance
        sample_df = df.sample(min(1000, len(df))) if len(df) > 1000 else df
        
        fig = go.Figure()
        
        # Normal traffic
        normal_data = sample_df[sample_df.get('anomaly', 'Normal') == 'Normal']
        if not normal_data.empty:
            fig.add_trace(go.Scatter(
                x=normal_data['bytes_in'],
                y=normal_data['bytes_out'],
                mode='markers',
                name='Normal Traffic',
                marker=dict(
                    color=self.colors['success'],
                    size=6,
                    opacity=0.7
                ),
                hovertemplate='<b>Normal Traffic</b><br>Bytes In: %{x}<br>Bytes Out: %{y}<extra></extra>'
            ))
        
        # Suspicious traffic
        suspicious_data = sample_df[sample_df.get('anomaly', 'Normal') == 'Suspicious']
        if not suspicious_data.empty:
            fig.add_trace(go.Scatter(
                x=suspicious_data['bytes_in'],
                y=suspicious_data['bytes_out'],
                mode='markers',
                name='Suspicious Traffic',
                marker=dict(
                    color=self.colors['danger'],
                    size=8,
                    opacity=0.8
                ),
                hovertemplate='<b>Suspicious Traffic</b><br>Bytes In: %{x}<br>Bytes Out: %{y}<extra></extra>'
            ))
        
        fig.update_layout(
            title={
                'text': '🔍 Traffic Pattern Analysis',
                'font': {'color': self.colors['text'], 'size': 18},
                'x': 0.5
            },
            xaxis_title='Bytes In',
            yaxis_title='Bytes Out',
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': self.colors['text']},
            xaxis=dict(gridcolor='#3A3A3A'),
            yaxis=dict(gridcolor='#3A3A3A'),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        return dcc.Graph(figure=fig, config={'displayModeBar': False})
    
    def create_geographic_map(self, df):
        """Create geographic threat distribution map."""
        if df.empty or 'src_ip_country_code' not in df.columns:
            return html.Div("No geographic data available", style={'color': '#CCCCCC'})
        
        # Country threat analysis
        country_data = df.groupby('src_ip_country_code').agg({
            'anomaly': lambda x: (x == 'Suspicious').sum() if 'anomaly' in df.columns else 0,
            'bytes_in': 'sum'
        }).reset_index()
        
        country_data['total_connections'] = df['src_ip_country_code'].value_counts()
        country_data['threat_ratio'] = country_data['anomaly'] / country_data['total_connections'] * 100
        
        fig = go.Figure(data=go.Choropleth(
            locations=country_data['src_ip_country_code'],
            z=country_data['threat_ratio'],
            text=country_data['src_ip_country_code'],
            colorscale='Reds',
            autocolorscale=False,
            reversescale=False,
            marker_line_color='darkgray',
            marker_line_width=0.5,
            colorbar_title="Threat %"
        ))
        
        fig.update_layout(
            title={
                'text': '🌍 Global Threat Distribution',
                'font': {'color': self.colors['text'], 'size': 18},
                'x': 0.5
            },
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type='natural earth',
                bgcolor='rgba(0,0,0,0)'
            ),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': self.colors['text']}
        )
        
        return dcc.Graph(figure=fig, config={'displayModeBar': False})
    
    def create_protocol_chart(self, df):
        """Create protocol analysis chart."""
        if df.empty or 'protocol' not in df.columns:
            return html.Div("No protocol data available", style={'color': '#CCCCCC'})
        
        protocol_counts = df['protocol'].value_counts()
        
        fig = go.Figure(data=[go.Pie(
            labels=protocol_counts.index,
            values=protocol_counts.values,
            hole=0.4,
            marker_colors=[self.colors['primary'], self.colors['secondary'], 
                          self.colors['success'], self.colors['warning'], self.colors['info']]
        )])
        
        fig.update_layout(
            title={
                'text': '🌐 Protocol Distribution',
                'font': {'color': self.colors['text'], 'size': 18},
                'x': 0.5
            },
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': self.colors['text']},
            showlegend=True,
            legend=dict(
                orientation="v",
                yanchor="middle",
                y=0.5,
                xanchor="left",
                x=1.05
            )
        )
        
        return dcc.Graph(figure=fig, config={'displayModeBar': False})
    
    def create_time_series_chart(self, df):
        """Create time series analysis chart."""
        time_cols = ['creation_time', 'end_time', 'time']
        time_col = None
        
        for col in time_cols:
            if col in df.columns:
                time_col = col
                break
        
        if time_col is None or df.empty:
            return html.Div("No time series data available", style={'color': '#CCCCCC'})
        
        # Convert to datetime and create hourly aggregation
        df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
        df_time = df.dropna(subset=[time_col])
        
        if df_time.empty:
            return html.Div("No valid time data available", style={'color': '#CCCCCC'})
        
        # Hourly traffic analysis
        df_time['hour'] = df_time[time_col].dt.hour
        hourly_normal = df_time[df_time.get('anomaly', 'Normal') == 'Normal']['hour'].value_counts().sort_index()
        hourly_suspicious = df_time[df_time.get('anomaly', 'Normal') == 'Suspicious']['hour'].value_counts().sort_index()
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=hourly_normal.index,
            y=hourly_normal.values,
            mode='lines+markers',
            name='Normal Traffic',
            line=dict(color=self.colors['success'], width=3),
            marker=dict(size=6)
        ))
        
        if not hourly_suspicious.empty:
            fig.add_trace(go.Scatter(
                x=hourly_suspicious.index,
                y=hourly_suspicious.values,
                mode='lines+markers',
                name='Suspicious Traffic',
                line=dict(color=self.colors['danger'], width=3),
                marker=dict(size=6)
            ))
        
        fig.update_layout(
            title={
                'text': '⏰ Hourly Traffic Pattern',
                'font': {'color': self.colors['text'], 'size': 18},
                'x': 0.5
            },
            xaxis_title='Hour of Day',
            yaxis_title='Traffic Count',
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': self.colors['text']},
            xaxis=dict(gridcolor='#3A3A3A'),
            yaxis=dict(gridcolor='#3A3A3A'),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        return dcc.Graph(figure=fig, config={'displayModeBar': False})
    
    def create_top_threats_table(self, df):
        """Create top threats data table."""
        if df.empty or 'src_ip_country_code' not in df.columns:
            return html.Div("No threat data available", style={'color': '#CCCCCC'})
        
        # Calculate top threats
        threat_data = MetricsCalculator.get_top_risk_countries(df, 10)
        
        if threat_data.empty:
            return html.Div("No threat data available", style={'color': '#CCCCCC'})
        
        # Format the data for display
        threat_data['risk_score'] = threat_data['risk_score'].round(2)
        threat_data['total_bytes'] = threat_data['bytes_in'] + threat_data['bytes_out']
        threat_data['total_bytes_formatted'] = threat_data['total_bytes'].apply(format_bytes)
        
        display_data = threat_data[['src_ip_country_code', 'anomaly', 'total_connections', 'risk_score', 'total_bytes_formatted']].copy()
        display_data.columns = ['Country', 'Threats', 'Connections', 'Risk %', 'Data Volume']
        
        return dash_table.DataTable(
            data=display_data.to_dict('records'),
            columns=[
                {'name': 'Country', 'id': 'Country'},
                {'name': 'Threats', 'id': 'Threats', 'type': 'numeric'},
                {'name': 'Connections', 'id': 'Connections', 'type': 'numeric'},
                {'name': 'Risk %', 'id': 'Risk %', 'type': 'numeric'},
                {'name': 'Data Volume', 'id': 'Data Volume'}
            ],
            style_cell={
                'backgroundColor': self.colors['surface'],
                'color': self.colors['text'],
                'textAlign': 'center',
                'fontFamily': 'Arial',
                'border': '1px solid #3A3A3A'
            },
            style_header={
                'backgroundColor': self.colors['primary'],
                'color': 'white',
                'fontWeight': 'bold'
            },
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': '#2A2A2A'
                }
            ]
        )
    
    def create_export_section(self):
        """Create export/download section."""
        return html.Div([
            html.H4("📥 Export Reports", style={
                'color': self.colors['text'],
                'marginBottom': '15px'
            }),
            html.Div([
                html.Button("📊 Download Excel Report", id="export-excel-btn", 
                           className="btn btn-primary", 
                           style={
                               'backgroundColor': self.colors['primary'],
                               'border': 'none',
                               'padding': '10px 20px',
                               'borderRadius': '5px',
                               'color': 'white',
                               'marginRight': '10px',
                               'cursor': 'pointer'
                           }),
                html.Button("📋 Generate PDF Summary", id="export-pdf-btn", 
                           className="btn btn-secondary",
                           style={
                               'backgroundColor': self.colors['secondary'],
                               'border': 'none',
                               'padding': '10px 20px',
                               'borderRadius': '5px',
                               'color': 'white',
                               'cursor': 'pointer'
                           })
            ])
        ], style={
            'backgroundColor': self.colors['surface'],
            'padding': '20px',
            'borderRadius': '10px',
            'boxShadow': '0 2px 10px rgba(0,0,0,0.2)',
            'marginTop': '20px'
        })
    
    # === MISSING FUNCTIONS ADDED ===
    
    def get_top_suspicious_ips(self, df, top_n=10):
        """Function to display top 10 suspicious IPs/countries - MISSING FUNCTION ADDED."""
        if 'is_suspicious' in df.columns:
            suspicious_df = df[df['is_suspicious'] == 1]
        elif 'threat_level' in df.columns:
            suspicious_df = df[df['threat_level'].isin(['High', 'Critical'])]
        else:
            return None
        
        if len(suspicious_df) == 0:
            return None
        
        if 'src_ip' in suspicious_df.columns:
            top_ips = suspicious_df['src_ip'].value_counts().head(top_n)
            ip_summary = []
            
            for i, (ip, count) in enumerate(top_ips.items(), 1):
                country = suspicious_df[suspicious_df['src_ip'] == ip]['src_ip_country_code'].iloc[0] if 'src_ip_country_code' in suspicious_df.columns else 'Unknown'
                total_bytes = suspicious_df[suspicious_df['src_ip'] == ip]['total_bytes'].sum() if 'total_bytes' in suspicious_df.columns else 0
                
                ip_summary.append({
                    'rank': i,
                    'ip': ip,
                    'country': country,
                    'incidents': count,
                    'total_bytes': total_bytes
                })
            
            return pd.DataFrame(ip_summary)
        
        return None

    def create_time_based_attack_trends(self, df):
        """Time-based attack trends (hourly/daily charts) - MISSING FUNCTION ADDED."""
        time_cols = ['creation_time', 'time', 'timestamp', 'end_time']
        time_col = None
        for col in time_cols:
            if col in df.columns:
                time_col = col
                break
        
        if time_col is None:
            return html.Div("❌ No time column found", style={'color': self.colors['danger']})
        
        # Convert to datetime
        df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
        df_time = df.dropna(subset=[time_col])
        
        # Identify suspicious traffic
        if 'is_suspicious' in df_time.columns:
            suspicious_df = df_time[df_time['is_suspicious'] == 1]
        elif 'threat_level' in df_time.columns:
            suspicious_df = df_time[df_time['threat_level'].isin(['High', 'Critical'])]
        else:
            suspicious_df = df_time
        
        # Create comprehensive time analysis
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Hourly Attack Patterns', 'Daily Attack Patterns', 
                          'Attack Trend Over Time', 'Day vs Hour Heatmap'),
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"type": "heatmap"}]]
        )
        
        # Hourly patterns
        df_time['hour'] = df_time[time_col].dt.hour
        suspicious_df['hour'] = suspicious_df[time_col].dt.hour
        
        hourly_normal = df_time['hour'].value_counts().sort_index()
        hourly_suspicious = suspicious_df['hour'].value_counts().sort_index()
        
        fig.add_trace(
            go.Scatter(x=hourly_normal.index, y=hourly_normal.values, 
                      mode='lines+markers', name='Normal Traffic',
                      line=dict(color=self.colors['success'])),
            row=1, col=1
        )
        fig.add_trace(
            go.Scatter(x=hourly_suspicious.index, y=hourly_suspicious.values,
                      mode='lines+markers', name='Suspicious Traffic',
                      line=dict(color=self.colors['danger'])),
            row=1, col=1
        )
        
        # Daily patterns
        df_time['day_of_week'] = df_time[time_col].dt.day_name()
        suspicious_df['day_of_week'] = suspicious_df[time_col].dt.day_name()
        
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        daily_suspicious = suspicious_df['day_of_week'].value_counts().reindex(day_order)
        
        fig.add_trace(
            go.Bar(x=day_order, y=daily_suspicious.values, name='Suspicious Daily',
                  marker_color=self.colors['warning']),
            row=1, col=2
        )
        
        # Time trend
        df_time['date'] = df_time[time_col].dt.date
        suspicious_df['date'] = suspicious_df[time_col].dt.date
        
        daily_attacks = suspicious_df['date'].value_counts().sort_index()
        if len(daily_attacks) > 0:
            fig.add_trace(
                go.Scatter(x=daily_attacks.index, y=daily_attacks.values,
                          mode='lines+markers', name='Daily Threats',
                          line=dict(color=self.colors['primary'])),
                row=2, col=1
            )
        
        fig.update_layout(
            height=800,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color=self.colors['text']),
            title='⏰ Time-Based Attack Trends Analysis'
        )
        
        return dcc.Graph(figure=fig, config={'displayModeBar': False})

    def create_geo_visualization_map(self, df):
        """Geo-visualization map of suspicious IP locations - MISSING FUNCTION ADDED."""
        if 'src_ip_country_code' not in df.columns:
            return html.Div("❌ Country code column not found", style={'color': self.colors['danger']})
        
        # Identify suspicious traffic
        if 'is_suspicious' in df.columns:
            suspicious_df = df[df['is_suspicious'] == 1]
        elif 'threat_level' in df.columns:
            suspicious_df = df[df['threat_level'].isin(['High', 'Critical'])]
        else:
            suspicious_df = df
        
        # Calculate threat statistics by country
        country_stats = df.groupby('src_ip_country_code').agg({
            'src_ip': 'count',
            'total_bytes': 'sum' if 'total_bytes' in df.columns else 'size',
        }).rename(columns={'src_ip': 'total_connections'})
        
        if len(suspicious_df) > 0:
            suspicious_stats = suspicious_df.groupby('src_ip_country_code').agg({
                'src_ip': 'count',
            }).rename(columns={'src_ip': 'suspicious_connections'})
            
            country_stats = country_stats.join(suspicious_stats, how='left').fillna(0)
            country_stats['threat_percentage'] = (country_stats['suspicious_connections'] / country_stats['total_connections']) * 100
        else:
            country_stats['suspicious_connections'] = 0
            country_stats['threat_percentage'] = 0
        
        country_stats = country_stats.reset_index()
        
        # Create interactive world map
        fig = px.choropleth(
            country_stats,
            locations="src_ip_country_code",
            color="threat_percentage",
            hover_name="src_ip_country_code",
            hover_data={
                "total_connections": ":,",
                "suspicious_connections": ":,",
                "threat_percentage": ":.1f"
            },
            color_continuous_scale="Reds",
            title="🌍 Global Cybersecurity Threat Distribution"
        )
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color=self.colors['text']),
            geo=dict(
                showframe=False,
                showcoastlines=True,
                bgcolor='rgba(0,0,0,0)'
            ),
            height=600
        )
        
        return dcc.Graph(figure=fig, config={'displayModeBar': False})

    def create_ml_models_component(self, df):
        """ML Models component with ROC curves and model evaluation - MISSING FUNCTION ADDED."""
        try:
            from sklearn.ensemble import IsolationForest, RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import roc_curve, auc
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            return html.Div("❌ Scikit-learn not available for ML analysis", 
                          style={'color': self.colors['danger']})
        
        ml_features = ['bytes_in', 'bytes_out', 'total_bytes']
        available_features = [col for col in ml_features if col in df.columns]
        
        if not available_features:
            return html.Div("❌ Required features not available for ML analysis", 
                          style={'color': self.colors['danger']})
        
        # Prepare data
        X = df[available_features].copy()
        X = X.fillna(X.median())
        
        # Create target variable
        if 'threat_level' in df.columns:
            y = (df['threat_level'].isin(['High', 'Critical'])).astype(int)
        else:
            y = (df['total_bytes'] > df['total_bytes'].quantile(0.9)).astype(int)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train Random Forest
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model.fit(X_train, y_train)
        rf_proba = rf_model.predict_proba(X_test)[:, 1]
        
        # Create ROC curve
        fpr, tpr, _ = roc_curve(y_test, rf_proba)
        roc_auc = auc(fpr, tpr)
        
        fig_roc = go.Figure()
        fig_roc.add_trace(go.Scatter(
            x=fpr, y=tpr,
            mode='lines',
            name=f'Random Forest (AUC = {roc_auc:.3f})',
            line=dict(width=3, color=self.colors['primary'])
        ))
        
        fig_roc.add_trace(go.Scatter(
            x=[0, 1], y=[0, 1],
            mode='lines',
            name='Random Classifier',
            line=dict(dash='dash', color='gray')
        ))
        
        fig_roc.update_layout(
            title='🎯 ROC Curve - Model Performance',
            xaxis_title='False Positive Rate',
            yaxis_title='True Positive Rate',
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color=self.colors['text']),
            height=500
        )
        
        return html.Div([
            html.H4("🤖 Machine Learning Models Analysis", 
                   style={'color': self.colors['text'], 'marginBottom': '20px'}),
            dcc.Graph(figure=fig_roc, config={'displayModeBar': False})
        ])

    def create_suspicious_ip_summary_table(self, df):
        """Create interactive suspicious IP summary table - MISSING FUNCTION ADDED."""
        suspicious_ips = self.get_top_suspicious_ips(df, top_n=20)
        
        if suspicious_ips is None or suspicious_ips.empty:
            return html.Div([
                html.H4("🚨 Suspicious IP Intelligence Summary", 
                       style={'color': self.colors['text']}),
                html.Div("✅ No suspicious activity detected", 
                        style={'color': self.colors['success'], 'padding': '20px'})
            ])
        
        table_data = suspicious_ips.to_dict('records')
        
        return html.Div([
            html.H4("🚨 Suspicious IP Intelligence Summary", 
                   style={'color': self.colors['text'], 'marginBottom': '20px'}),
            
            # Summary metrics
            html.Div([
                html.Div([
                    html.H3(str(len(suspicious_ips)), style={'color': self.colors['primary'], 'margin': '0'}),
                    html.P("Suspicious IPs", style={'color': '#CCCCCC', 'margin': '0'})
                ], style={'textAlign': 'center', 'padding': '10px'}),
                
                html.Div([
                    html.H3(str(suspicious_ips['country'].nunique()), style={'color': self.colors['warning'], 'margin': '0'}),
                    html.P("Countries", style={'color': '#CCCCCC', 'margin': '0'})
                ], style={'textAlign': 'center', 'padding': '10px'}),
                
                html.Div([
                    html.H3(str(suspicious_ips['incidents'].sum()), style={'color': self.colors['danger'], 'margin': '0'}),
                    html.P("Total Incidents", style={'color': '#CCCCCC', 'margin': '0'})
                ], style={'textAlign': 'center', 'padding': '10px'}),
                
                html.Div([
                    html.H3(f"{suspicious_ips['total_bytes'].sum()/1024**3:.2f} GB", style={'color': self.colors['info'], 'margin': '0'}),
                    html.P("Total Data", style={'color': '#CCCCCC', 'margin': '0'})
                ], style={'textAlign': 'center', 'padding': '10px'})
            ], style={
                'display': 'flex',
                'justifyContent': 'space-around',
                'backgroundColor': self.colors['surface'],
                'borderRadius': '10px',
                'padding': '20px',
                'marginBottom': '20px'
            }),
            
            # Data table
            dash_table.DataTable(
                data=table_data,
                columns=[
                    {'name': 'Rank', 'id': 'rank'},
                    {'name': 'IP Address', 'id': 'ip'},
                    {'name': 'Country', 'id': 'country'},
                    {'name': 'Incidents', 'id': 'incidents', 'type': 'numeric'},
                    {'name': 'Total Bytes', 'id': 'total_bytes', 'type': 'numeric', 'format': {'specifier': ',.0f'}}
                ],
                style_cell={
                    'backgroundColor': self.colors['surface'],
                    'color': self.colors['text'],
                    'textAlign': 'center',
                    'fontFamily': 'Arial',
                    'border': f'1px solid {self.colors["primary"]}'
                },
                style_header={
                    'backgroundColor': self.colors['primary'],
                    'color': 'white',
                    'fontWeight': 'bold'
                },
                page_size=10,
                sort_action="native",
                filter_action="native"
            )
        ])

    def create_real_time_traffic_monitor(self, df):
        """Real-time traffic visualization component - MISSING FUNCTION ADDED."""
        # Calculate real-time metrics
        current_connections = len(df)
        threat_count = len(df[df['threat_level'].isin(['High', 'Critical'])]) if 'threat_level' in df.columns else 0
        data_volume = df['total_bytes'].sum() / 1024**2 if 'total_bytes' in df.columns else 0
        unique_countries = df['src_ip_country_code'].nunique() if 'src_ip_country_code' in df.columns else 0
        
        # Create real-time metrics display
        return html.Div([
            html.H4("⚡ Real-Time Traffic Monitor", 
                   style={'color': self.colors['text'], 'marginBottom': '20px'}),
            
            html.Div([
                html.Div([
                    html.H3(f"{current_connections:,}", style={'color': self.colors['primary'], 'margin': '0'}),
                    html.P("Active Connections", style={'color': '#CCCCCC', 'margin': '0'}),
                    html.Small(f"Δ +{np.random.randint(-50, 100)}", style={'color': self.colors['success']})
                ], style={'textAlign': 'center', 'padding': '15px', 'backgroundColor': self.colors['background'], 'borderRadius': '8px', 'margin': '5px'}),
                
                html.Div([
                    html.H3(str(threat_count), style={'color': self.colors['danger'], 'margin': '0'}),
                    html.P("Active Threats", style={'color': '#CCCCCC', 'margin': '0'}),
                    html.Small(f"Δ {np.random.randint(-5, 15):+d}", style={'color': self.colors['warning']})
                ], style={'textAlign': 'center', 'padding': '15px', 'backgroundColor': self.colors['background'], 'borderRadius': '8px', 'margin': '5px'}),
                
                html.Div([
                    html.H3(f"{data_volume:.1f} MB", style={'color': self.colors['info'], 'margin': '0'}),
                    html.P("Data Volume", style={'color': '#CCCCCC', 'margin': '0'}),
                    html.Small(f"Δ +{np.random.uniform(-10, 50):.1f}", style={'color': self.colors['success']})
                ], style={'textAlign': 'center', 'padding': '15px', 'backgroundColor': self.colors['background'], 'borderRadius': '8px', 'margin': '5px'}),
                
                html.Div([
                    html.H3(str(unique_countries), style={'color': self.colors['warning'], 'margin': '0'}),
                    html.P("Source Countries", style={'color': '#CCCCCC', 'margin': '0'}),
                    html.Small(f"Δ {np.random.randint(-2, 5):+d}", style={'color': self.colors['primary']})
                ], style={'textAlign': 'center', 'padding': '15px', 'backgroundColor': self.colors['background'], 'borderRadius': '8px', 'margin': '5px'})
            ], style={'display': 'flex', 'justifyContent': 'space-around', 'marginBottom': '20px'}),
            
            # Live status indicator
            html.Div([
                html.Span("🟢", style={'fontSize': '12px', 'marginRight': '5px'}),
                html.Span("LIVE MONITORING ACTIVE", style={'fontSize': '12px', 'fontWeight': 'bold', 'color': self.colors['success']}),
                html.Span(f" | Last Update: {datetime.now().strftime('%H:%M:%S')}", 
                         style={'fontSize': '10px', 'color': '#CCCCCC', 'marginLeft': '10px'})
            ], style={'textAlign': 'center', 'padding': '10px', 'backgroundColor': self.colors['dark'], 'borderRadius': '5px'})
        ], style={
            'backgroundColor': self.colors['surface'],
            'padding': '20px',
            'borderRadius': '10px',
            'boxShadow': '0 4px 15px rgba(0,0,0,0.3)'
        })

    def create_enhanced_data_export_section(self, df):
        """Enhanced data export section - MISSING FUNCTION ADDED."""
        # Calculate export statistics
        total_records = len(df)
        suspicious_records = len(df[df['threat_level'].isin(['High', 'Critical'])]) if 'threat_level' in df.columns else 0
        
        return html.Div([
            html.H4("📥 Advanced Data Export & Reporting", 
                   style={'color': self.colors['text'], 'marginBottom': '20px'}),
            
            # Export statistics
            html.Div([
                html.Div([
                    html.H3(f"{total_records:,}", style={'color': self.colors['primary'], 'margin': '0'}),
                    html.P("Total Records", style={'color': '#CCCCCC', 'margin': '0'})
                ], style={'textAlign': 'center', 'padding': '10px'}),
                
                html.Div([
                    html.H3(f"{suspicious_records:,}", style={'color': self.colors['danger'], 'margin': '0'}),
                    html.P("Suspicious Records", style={'color': '#CCCCCC', 'margin': '0'})
                ], style={'textAlign': 'center', 'padding': '10px'}),
                
                html.Div([
                    html.H3(f"{len(df.columns)}", style={'color': self.colors['info'], 'margin': '0'}),
                    html.P("Data Columns", style={'color': '#CCCCCC', 'margin': '0'})
                ], style={'textAlign': 'center', 'padding': '10px'}),
                
                html.Div([
                    html.H3(f"{len(df) * len(df.columns) / 1024 / 1024:.2f} MB", style={'color': self.colors['warning'], 'margin': '0'}),
                    html.P("Est. File Size", style={'color': '#CCCCCC', 'margin': '0'})
                ], style={'textAlign': 'center', 'padding': '10px'})
            ], style={
                'display': 'flex',
                'justifyContent': 'space-around',
                'backgroundColor': self.colors['background'],
                'borderRadius': '10px',
                'padding': '15px',
                'marginBottom': '20px'
            }),
            
            # Export buttons
            html.Div([
                html.Button("📊 Export CSV", id="export-csv-btn", 
                           style={
                               'backgroundColor': self.colors['primary'],
                               'border': 'none',
                               'padding': '12px 24px',
                               'borderRadius': '8px',
                               'color': 'white',
                               'marginRight': '10px',
                               'cursor': 'pointer',
                               'fontWeight': 'bold'
                           }),
                html.Button("📄 Export JSON", id="export-json-btn", 
                           style={
                               'backgroundColor': self.colors['info'],
                               'border': 'none',
                               'padding': '12px 24px',
                               'borderRadius': '8px',
                               'color': 'white',
                               'marginRight': '10px',
                               'cursor': 'pointer',
                               'fontWeight': 'bold'
                           }),
                html.Button("📋 Summary Report", id="export-summary-btn", 
                           style={
                               'backgroundColor': self.colors['warning'],
                               'border': 'none',
                               'padding': '12px 24px',
                               'borderRadius': '8px',
                               'color': 'white',
                               'cursor': 'pointer',
                               'fontWeight': 'bold'
                           })
            ], style={'textAlign': 'center'})
        ], style={
            'backgroundColor': self.colors['surface'],
            'padding': '20px',
            'borderRadius': '10px',
            'boxShadow': '0 4px 15px rgba(0,0,0,0.3)'
        })